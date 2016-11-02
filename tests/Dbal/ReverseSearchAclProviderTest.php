<?php
/**
 * This file is part of the Global Trading Technologies Ltd reverse-search-acl package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * (c) fduch <alex.medwedew@gmail.com>
 *
 * Date: 02.09.15
 */

namespace Gtt\Acl\Tests\Dbal;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Gtt\Acl\Dbal\ReverseSearchAclProvider;
use Gtt\Acl\Tests\Dbal\Fixtures\Person;
use Symfony\Component\Security\Acl\Dbal\Schema;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\PermissionGrantingStrategy;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Symfony\Component\Security\Acl\Permission\BasicPermissionMap;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;
use Symfony\Component\Security\Core\User\User;

class ReverseSearchAclProviderTest extends \PHPUnit_Framework_TestCase
{
    /**
     *  Acl provider
     *
     * @var ReverseSearchAclProvider
     */
    protected $aclProvider;

    /**
     * Sid from token
     *
     * @var SecurityIdentityInterface
     */
    protected $sid;

    /**
     * @var Connection
     */
    protected $con;

    protected function setUp()
    {
        if (!class_exists('PDO') || !in_array('sqlite', \PDO::getAvailableDrivers())) {
            self::markTestSkipped('This test requires SQLite support in your environment');
        }

        $this->con = DriverManager::getConnection([
            'driver' => 'pdo_sqlite',
            'memory' => true,
        ]);

        // import the schema
        $schema = new Schema($this->getOptions());
        foreach ($schema->toSql($this->con->getDatabasePlatform()) as $sql) {
            $this->con->exec($sql);
        }

        $this->sid = UserSecurityIdentity::fromAccount(new User('jimmy', 'jimmypass'));

        $this->aclProvider = $this->getProvider();
    }

    protected function tearDown()
    {
        $this->con = null;
    }

    public function testDenyingDoesNotAffectResult()
    {
        $oid = new ObjectIdentity('id', 'type');

        $acl = $this->aclProvider->createAcl($oid);
        $acl->insertObjectAce($this->sid, MaskBuilder::MASK_VIEW, 0, false);
        $this->aclProvider->updateAcl($acl);

        $this->assertEmpty($this->aclProvider->findObjectIdentities($this->sid, "VIEW"));
        $this->assertEmpty($this->aclProvider->findAllowedEntries($this->sid, "VIEW"));
    }

    public function testPermissionMapSupportWorks()
    {
        $oid = new ObjectIdentity('id', 'type');

        $acl = $this->aclProvider->createAcl($oid);
        $acl->insertObjectAce($this->sid, MaskBuilder::MASK_EDIT);
        $this->aclProvider->updateAcl($acl);

        $this->assertEquals(
            [$oid->getType() => [$oid]],
            $this->aclProvider->findObjectIdentities($this->sid, "VIEW")
        );
        $this->assertEquals(
            [$oid->getType() => ['object_access' => [$oid->getIdentifier()]]],
            $this->aclProvider->findAllowedEntries($this->sid, "VIEW")
        );
    }

    public function testGrantingWinsDenying()
    {
        $oid = new ObjectIdentity('id', 'type');

        $acl = $this->aclProvider->createAcl($oid);
        $acl->insertObjectAce($this->sid, MaskBuilder::MASK_VIEW);
        $acl->insertObjectAce($this->sid, MaskBuilder::MASK_VIEW, 0, false);
        $this->aclProvider->updateAcl($acl);

        $this->assertEquals(
            [$oid->getType() => [$oid]],
            $this->aclProvider->findObjectIdentities($this->sid, "VIEW")
        );
        $this->assertEquals(
            [$oid->getType() => ['object_access' => [$oid->getIdentifier()]]],
            $this->aclProvider->findAllowedEntries($this->sid, "VIEW")
        );
    }

    public function testStrategiesSupportWorks()
    {
        $maskBuilder = new MaskBuilder();

        $oid = new ObjectIdentity('id', 'type');

        $acl = $this->aclProvider->createAcl($oid);
        $acl->insertObjectAce(
            $this->sid,
            $maskBuilder->add(MaskBuilder::MASK_VIEW)->add(MaskBuilder::MASK_EDIT)->get(),
            0,
            true,
            PermissionGrantingStrategy::EQUAL
        );
        $this->aclProvider->updateAcl($acl);

        $this->assertEmpty($this->aclProvider->findObjectIdentities($this->sid, "VIEW"));
        $this->assertEmpty($this->aclProvider->findAllowedEntries($this->sid, "VIEW"));
    }

    public function testClassRestrictionWorks()
    {
        $oid1 = new ObjectIdentity('id1', 'type1');
        $oid2 = new ObjectIdentity('id2', 'type2');

        $acl = $this->aclProvider->createAcl($oid1);
        $acl->insertObjectAce($this->sid, MaskBuilder::MASK_VIEW);
        $this->aclProvider->updateAcl($acl);

        $acl = $this->aclProvider->createAcl($oid2);
        $acl->insertObjectAce($this->sid, MaskBuilder::MASK_VIEW);
        $this->aclProvider->updateAcl($acl);

        $this->assertEquals(
            [$oid2->getType() => [$oid2]],
            $this->aclProvider->findObjectIdentities($this->sid, "VIEW", ['class' => $oid2->getType()])
        );
        $this->assertEquals(
            [$oid2->getType() => ['object_access' => [$oid2->getIdentifier()]]],
            $this->aclProvider->findAllowedEntries($this->sid, "VIEW", ['class' => $oid2->getType()])
        );
    }

    public function testTheSameOidsForDifferentPermissionsAreNotDuplicated()
    {
        $oid = new ObjectIdentity('id', 'type');

        $acl = $this->aclProvider->createAcl($oid);
        $acl->insertObjectAce($this->sid, MaskBuilder::MASK_EDIT);
        $acl->insertObjectAce($this->sid, MaskBuilder::MASK_VIEW);
        $this->aclProvider->updateAcl($acl);

        $this->assertEquals(
            [$oid->getType() => [$oid]],
            $this->aclProvider->findObjectIdentities($this->sid, "VIEW")
        );
        $this->assertEquals(
            [$oid->getType() => ['object_access' => [$oid->getIdentifier()]]],
            $this->aclProvider->findAllowedEntries($this->sid, "VIEW")
        );
    }

    public function testFieldAndClassGrantsWorks()
    {
        $oid = new ObjectIdentity('10', Person::class);

        $acl = $this->aclProvider->createAcl($oid);

        $acl->insertClassFieldAce('name', $this->sid, MaskBuilder::MASK_VIEW);
        $acl->insertClassAce($this->sid, MaskBuilder::MASK_EDIT);
        $acl->insertObjectFieldAce('surname', $this->sid, MaskBuilder::MASK_VIEW);


        $this->aclProvider->updateAcl($acl);

        $this->assertEquals(
            [$oid->getType() => [
                    'class_access'       => true,
                    'class_field_access' => ['name'],
                    'object_field_access'   => [
                        $oid->getIdentifier() => ['surname']
                    ],
                ]
            ],
            $this->aclProvider->findAllowedEntries($this->sid, "VIEW")
        );
    }

    protected function getOptions()
    {
        return [
            'oid_table_name' => 'acl_object_identities',
            'oid_ancestors_table_name' => 'acl_object_identity_ancestors',
            'class_table_name' => 'acl_classes',
            'sid_table_name' => 'acl_security_identities',
            'entry_table_name' => 'acl_entries',
        ];
    }

    protected function getStrategy()
    {
        return new PermissionGrantingStrategy();
    }

    protected function getProvider($cache = null)
    {
        return new ReverseSearchAclProvider(new BasicPermissionMap(), $this->con, $this->getStrategy(), $this->getOptions(), $cache);
    }
}