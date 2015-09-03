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

Now you are ready to find which domain objects can see (permission VIEW) some user:

```php

$sid = UserSecurityIdentity::fromAccount(new User('jimmy', 'jimmypass'));

$grantedOids = $provider->findObjectIdentities($sid, "VIEW")
```

You can also restrict the search by specifying class and/or field of the allowed object identities to fetch:
```php
$grantedOids = $provider->findObjectIdentities(
    $sid,
    "VIEW",
    ['class' => \My\Domain\Object\Class, 'field' => 'some_field']
);
```

Restrictions
============

* Note that library reverse work of [PermissionGrantingStrategy](https://github.com/symfony/security-acl/blob/master/Domain/PermissionGrantingStrategy.php).
Use it with the other ones only if you know exactly what are you doing.

* Be careful if you are using [PermissionMapInterface](https://github.com/symfony/security-acl/blob/master/Permission/PermissionMapInterface.php) instances
that are really take in account specified object (second parameter in PermissionMapInterface::getMasks method) during
retrieving masks process (there are no such PermissionMapInterface implementations in Symfony for now, but anyway).

