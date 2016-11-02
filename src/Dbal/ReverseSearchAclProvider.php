<?php
/**
 * This file is part of the Global Trading Technologies Ltd reverse-search-acl package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * (c) fduch <alex.medwedew@gmail.com>
 *
 * @date 22.07.15
 */

namespace Gtt\Acl\Dbal;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Driver\Statement;
use Gtt\Acl\Exception\InvalidArgumentException;
use PDO;
use Symfony\Component\Security\Acl\Dbal\MutableAclProvider;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\PermissionGrantingStrategy;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Model\AclCacheInterface;
use Symfony\Component\Security\Acl\Model\PermissionGrantingStrategyInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Symfony\Component\Security\Acl\Permission\PermissionMapInterface;

/**
 * Acl provider extends the base one with ability to get granted oid's by sids
 * This class implements logic inversed to the logic of PermissionGrantingStrategy
 * More generally this provider allows to find list of oid's for specified sid and permission
 * like so this list of oid's would be voted for grant by PermissionGrantingStrategy for
 * such sid and permission
 *
 * @see PermissionGrantingStrategy
 */
class ReverseSearchAclProvider extends MutableAclProvider
{
    /**
     *  Defines pattern to check mask according to PermissionGrantingStrategy::{ALL, ANY, EQUAL} strategies
     *
     * @var array
     */
    protected static $permissionStrategyCheckPatterns = array(
        PermissionGrantingStrategy::ALL   => ":%MASK_PARAM% = e.mask & :%MASK_PARAM%",
        PermissionGrantingStrategy::ANY   => "e.mask & :%MASK_PARAM% != 0",
        PermissionGrantingStrategy::EQUAL => "e.mask = :%MASK_PARAM%",
    );

    /**
     * Permission map
     *
     * @var PermissionMapInterface
     */
    protected $permissionMap;

    /**
     * Constructor
     *
     * @param PermissionMapInterface $permissionMap permission map service
     *
     * {@inheritdoc}
     */
    public function __construct(
        PermissionMapInterface $permissionMap,
        Connection $connection,
        PermissionGrantingStrategyInterface $permissionGrantingStrategy,
        array $options,
        AclCacheInterface $cache = null)
    {
        parent::__construct($connection, $permissionGrantingStrategy, $options, $cache);
        $this->permissionMap = $permissionMap;
    }

    /**
     * Finds object identities by owner sid and additional filters
     * TODO implement cache (probably default acl cache can be used here)
     *
     * @param SecurityIdentityInterface $sid          owner sid
     * @param string                    $permission   permission for that object identities should be used ('VIEW', 'EDIT', etc)
     * @param array                     $aceFilter    ace filter with the following structure:
     *        array(
     *            "class"  class name of object identities to restrict the search
     *            "field"  field name of the class of object identities to restrict the search (class field should be set)
     *        )
     * @param bool                      $findChildren flag defines whether children object identities
     *                                                for found ones should be returned or not
     * @return array of object identities grouped by type
     */
    public function findObjectIdentities(SecurityIdentityInterface $sid, $permission, $aceFilter = array(), $findChildren = false)
    {
        // TODO implement oid search too
        if ($findChildren) {
            throw new InvalidArgumentException("Object identities children search is not implemented yet");
        }

        $valuesForBind = array();

        // sql restrictions based by parameters specified
        $sidSqlRestriction        = $this->getSidSqlRestriction($sid, $valuesForBind);
        $aceSqlRestriction        = $this->getAceSqlRestriction($aceFilter, $valuesForBind);
        $permissionSqlRestriction = $this->getPermissionSqlRestriction($permission, $valuesForBind);

        $pattern = <<<SELECTCLAUSE
            SELECT DISTINCT
                o.object_identifier,
                c.class_type
            FROM
                {$this->options['entry_table_name']} e
            INNER JOIN {$this->options['oid_table_name']} o ON o.id = e.object_identity_id
            %s
            %s
            %s
SELECTCLAUSE;
        $sql  = sprintf($pattern, $sidSqlRestriction, $aceSqlRestriction, $permissionSqlRestriction);
        $stmt = $this->connection->prepare($sql);

        // bind values
        $this->bindValuesToStatement($stmt, $valuesForBind);

        $objectIdentities = array();
        $stmt->execute();
        foreach ($stmt->fetchAll() as $data) {
            if (!isset($objectIdentities[$data['class_type']])) {
                $objectIdentities[$data['class_type']] = array();
            }
            $objectIdentities[$data['class_type']][] = new ObjectIdentity($data['object_identifier'], $data['class_type']);
        }

        return $objectIdentities;
    }

    /**
     * Constructs sql restriction based on permission specified and fills list of used sql params to be bind in prepared
     * statement
     *
     * @param string $permission     permission value (VIEW, EDIT, etc)
     * @param array  &$valuesForBind list of params to be bind
     *
     * @return string
     */
    private function getPermissionSqlRestriction($permission, &$valuesForBind)
    {
        if (!$this->permissionMap->contains($permission)) {
            throw new InvalidArgumentException(sprintf('There is no masks in permission map for specified permission "%s"', $permission));
        }

        // Hack to omit mandatory object parameter which is not necessary
        $requiredMasks = $this->permissionMap->getMasks($permission, new \StdClass());
        $maskSqlParams = array();

        // filling values for bind with mask params and prepare mask params array
        foreach ($requiredMasks as $maskKey => $mask) {
            $maskParam = "mask" . $maskKey;
            $maskSqlParams[$maskKey] = $maskParam;
            $valuesForBind[$maskParam] = array('value' => $mask, 'type' => PDO::PARAM_INT);
        }

        $strategyMasksSqlRestrictions = array();
        foreach (static::$permissionStrategyCheckPatterns as $strategyKey => $pattern) {
            $strategyMasksSqlRestrictions[$strategyKey] = array();
            foreach ($requiredMasks as $maskKey => $mask) {
                $strategyMasksSqlRestrictions[$strategyKey][] = str_replace("%MASK_PARAM%", $maskSqlParams[$maskKey], $pattern);
            }
        }

        $strategySqlRestrictions = array();
        foreach ($strategyMasksSqlRestrictions as $strategyKey => $restrictions) {
            $strategySqlRestrictions[] = sprintf('(e.granting_strategy = "%s" AND (%s))', $strategyKey, implode(" OR ", $restrictions));
        }

        $permissionSqlRestriction = sprintf('WHERE e.granting = 1 AND (%s)', implode(" OR ", $strategySqlRestrictions));

        return $permissionSqlRestriction;
    }

    /**
     * Constructs sql restriction based on ace class and field specified as array and fills list
     * of used sql params to be bind in prepared statement
     *
     * @param array $aceFilter      ace filter
     * @param array &$valuesForBind list of params to be bind
     *
     * @return string
     */
    private function getAceSqlRestriction($aceFilter, &$valuesForBind)
    {
        $aceSqlRestriction = sprintf("INNER JOIN %s c ON c.id = e.class_id", $this->options['class_table_name']);

        if (!empty($aceFilter['field']) && empty($aceFilter['class'])) {
            throw new InvalidArgumentException("Class ace filter must be specified when field filter is used");
        }

        if (!empty($aceFilter['class'])) {
            $aceSqlRestriction .= " AND c.class_type = :class";
            $valuesForBind['class'] = array('value' => $aceFilter['class'], 'type' => PDO::PARAM_STR);
        }

        if (!empty($aceFilter['field'])) {
            $aceSqlRestriction .= " AND e.field_name = :field";
            $valuesForBind['field'] = array('value' => $aceFilter['field'], 'type' => PDO::PARAM_STR);
        }

        return $aceSqlRestriction;
    }

    /**
     * Constructs sql restriction based on sid specified as array and fills list
     * of used sql params to be bind in prepared statement
     *
     * @param SecurityIdentityInterface $sid            sid
     * @param array                     &$valuesForBind list of params to be bind
     *
     * @return string
     */
    private function getSidSqlRestriction(SecurityIdentityInterface $sid, &$valuesForBind)
    {
        if ($sid instanceof UserSecurityIdentity) {
            $identifier = $sid->getClass() . '-' . $sid->getUsername();
            $isUsername = true;
        } elseif ($sid instanceof RoleSecurityIdentity) {
            $identifier = $sid->getRole();
            $isUsername = false;
        } else {
            throw new InvalidArgumentException('$sid must either be an instance of UserSecurityIdentity, or RoleSecurityIdentity.');
        }

        $sidSqlRestriction = sprintf(
            "INNER JOIN %s s ON e.security_identity_id = s.id AND s.identifier = :identifier AND s.username = :username",
            $this->options['sid_table_name']
        );

        $valuesForBind['identifier'] = array('value' => $identifier, 'type' => PDO::PARAM_STR);
        $valuesForBind['username']   = array('value' => $isUsername, 'type' => PDO::PARAM_BOOL);

        return $sidSqlRestriction;
    }

    /**
     * Binds values to the prepared statement
     *
     * @param Statement $stmt          statement
     * @param array     $valuesForBind values to bind in following structure:
     *        array(
     *            "key"        name of parameter in statement
     *             => array(
     *                "value"  value of the parameter
     *                "type"   type of the parameter (optional)
     *            )
     *        )
     */
    private function bindValuesToStatement(Statement $stmt, $valuesForBind)
    {
        foreach ($valuesForBind as $key => $data) {
            if (isset($data['type'])) {
                $stmt->bindValue($key, $data['value'], $data['type']);
            } else {
                $stmt->bindValue($key, $data['value']);
            }
        }
    }
}