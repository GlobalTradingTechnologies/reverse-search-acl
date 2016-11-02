<?php
/**
 * This file is part of the Global Trading Technologies Ltd workflow-extension-bundle package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * (c) fduch <alex.medwedew@gmail.com>
 *
 * Date: 01.11.16
 */

namespace Gtt\Acl\Tests\Dbal\Fixtures;

/**
 * Description
 *
 * @author fduch <alex.medwedew@gmail.com>
 */
class Person
{
    private $id;

    private $name;

    private $surname;

    /**
     * Person constructor.
     *
     * @param $id
     * @param $name
     * @param $surname
     * @param $salary
     */
    public function __construct($id, $name, $surname, $salary)
    {
        $this->id      = $id;
        $this->name    = $name;
        $this->surname = $surname;
        $this->salary  = $salary;
    }

    /**
     * @return mixed
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @return mixed
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * @return mixed
     */
    public function getSurname()
    {
        return $this->surname;
    }
}
