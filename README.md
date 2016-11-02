Symfony ACL reverse search component
====================================

[![Build Status](https://travis-ci.org/GlobalTradingTechnologies/reverse-search-acl.svg?branch=master)](https://travis-ci.org/GlobalTradingTechnologies/reverse-search-acl)
[![Latest Stable Version](https://poser.pugx.org/gtt/reverse-search-acl/v/stable)](https://packagist.org/packages/gtt/reverse-search-acl)
[![Latest Unstable Version](https://poser.pugx.org/gtt/reverse-search-acl/v/unstable)](https://packagist.org/packages/gtt/reverse-search-acl)
[![License](https://poser.pugx.org/gtt/reverse-search-acl/license)](https://packagist.org/packages/gtt/reverse-search-acl)

This library extends base Symfony's [MutableAclProvider](https://github.com/symfony/security-acl/blob/master/Dbal/MutableAclProvider.php)
with ability to find accessible object identities for specified security identity. You can also specify permission Ace
was granted for target security identity with.

This library provides convenient way create admin interfaces for ACL-based systems where you need to show assigned
domain objects and permissions for fetched for requested single user in the system


Requirements
============

Library requires Symfony's security-acl package and doctrine/dbal component to interact with acl database

How it works?
=============

As was said above the library contains extended acl provider - ReverseSearchAclProvider. Basically there is nothing
more inside. The main goal of this provider being is to do reverse action against [PermissionGrantingStrategy](https://github.com/symfony/security-acl/blob/master/Domain/PermissionGrantingStrategy.php) does when it checks
whether specified SecurityIdentity has access (the type of access is restricted by permission: VIEW, EDIT, etc) to specified ObjectIdentity or not.
Due to performance reasons (which were actually kept in mind during Symfony's ACL system designing)
ReverseSearchAclProvider solves this task by constructing and executing PDO statement similar to the other ones in
[AclProvider](https://github.com/symfony/security-acl/blob/master/Dbal/AclProvider.php).

Installation
============

Library can by installed with composer quite easy:
```
composer require gtt/reverse-search-acl
```

Usage
=====

In order to create instance of ReverseSearchAclProvider you need to specify the same constructor parameters that
are required for MutableAclProvider and prepend this list with the instance of [PermissionMapInterface](https://github.com/symfony/security-acl/blob/master/Permission/PermissionMapInterface.php) (since ReverseSearchAclProvider
needs to translate specified permission to masks):

```php
use Gtt\Acl\Dbal\ReverseSearchAclProvider;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Permission\BasicPermissionMap;
use Symfony\Component\Security\Acl\Permission\BasicPermissionMap;
use Doctrine\DBAL\DriverManager;

$provider = new ReverseSearchAclProvider(
    new BasicPermissionMap()
    DriverManager::getConnection(['driver' => 'pdo_sqlite','memory' => true],
    new PermissionGrantingStrategy(),
    [] // list of base acl provider options
);
```

Now you are ready to find which domain objects (or classes itself or class/object fields) can see (permission VIEW) some user or role:

```php

$sid = UserSecurityIdentity::fromAccount(new User('jimmy', 'jimmypass'));
// you can also analyse roles
// $sid = new RoleSecurityIdentity('ROLE_ADMIN');

$allowed = $provider->findAllowedEntries($sid, "VIEW")
```
The returned result will be an array with the following structure
```php
[
    // the key is FQCN of the class of the object that can be accessed by specified Security Identity instance (SID)
    '\F\Q\C\N' => [
        // if this flag is presented class ace was inserted for current SID
        'class_access'        => true,
        // list of class field's granted to current SID
        'class_field_access'  => ['field1', 'field2', 'field3'],
        // id of the domain objects accessible by current SID
        'object_access'       => ['id1', 'id2', 'id3', 'id4'],
        // list of domain object fields (grouped by object id) granted to current SID
        'object_field_access' => [
           'id2' => ['field1', 'field2'],
           'id5' => ['field3']
        ]
    ]
]
```

You can also restrict the search by specifying class and/or field of the allowed object identities to fetch:
```php
$allowed = $provider->findObjectIdentities(
    $sid,
    "VIEW",
    ['class' => \My\Domain\Object\Class]
);
```

Restrictions
============

* Note that library reverse work of [PermissionGrantingStrategy](https://github.com/symfony/security-acl/blob/master/Domain/PermissionGrantingStrategy.php).
Use it with the other ones only if you know exactly what are you doing.

* If you use the both object and class aces (or object field and class field aces) you should note the [PermissionGrantingStrategy](https://github.com/symfony/security-acl/blob/master/Domain/PermissionGrantingStrategy.php) during access decisions
consequentially checks object-level and then class-level ACE's to grant or deny access. Object and class access information returned by provider separately
so to be sure that current SID has (or doesn't have) access to current object you should take in account the both class and object access info (ie object_access/class_access or object_field_access/class_field_access).

* Be careful if you are using [PermissionMapInterface](https://github.com/symfony/security-acl/blob/master/Permission/PermissionMapInterface.php) instances
that are really take in account specified object (second parameter in PermissionMapInterface::getMasks method) during
retrieving masks process (there are no such PermissionMapInterface implementations in Symfony for now, but anyway).

