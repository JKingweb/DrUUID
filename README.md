DrUUID
======
An RFC 9562 (UUID) implementation for PHP.

Usage
-----
DrUUID's API has been designed to be as absolutely simple to use as possible. sGenerating a UUID is as simple as issuing a single method call:

```php
<?php
use JKingWeb\DrUUID\UUID;
echo UUID::mint();
?>
```

Compliance
----------
DrUUID fully complies with RFC 9562, and therefore supports all specified types of UUIDs:

```php
<?php
use JKingWeb\DrUUID\UUID;
echo UUID::mint(1)."\n";
echo UUID::mint(3, "some identifier", $private_namespace)."\n";
echo UUID::mint(4)."\n";
echo UUID::mint(5, "some identifier", $private_namespace)."\n";
echo UUID::mint(6)."\n";
echo UUID::mint(7)."\n";
```

More information
----------------

DrUUID includes an extensive and exhaustive HTML manual. A complete break-down of features and their use is available therein.
