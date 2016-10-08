<?php
/* This file implements a compatibility shim for existing users of DrUUID
   and acts as a drop-in replacement.  PHP 5.3 is nevertheless required,
   as is a usable autoloader (one is defined below, if necessary), but the
   library should act identically to how it did before being namespaced. 
   
   In particular:
   - One can still call UUID::mint() as before
   - `class_name($uuid)` continues to return "UUID"
   - `catch(UUIDException $e)` works as expected for either exception type
   - Storage classes which implemented UUIDStorage continue to work
*/

if(!@class_exists("JKingWeb\\DrUUID\\UUID")) { // checks for pre-existence of a compatible autoloader 
	spl_autoload_register(function ($class) {
		$base = __DIR__.DIRECTORY_SEPARATOR;
		$file = str_replace("\\", DIRECTORY_SEPARATOR, $class);
		$file = $base."vendor".DIRECTORY_SEPARATOR.$file.".php";
		if (file_exists($file)) {
			require_once $file;
		}
	});
}

interface UUIDStorage extends JKingWeb\DrUUID\UUIDStorage {}
class UUID extends JKingWeb\DrUUID\UUID {
	protected static $storeClass          = "\\UUIDStorageStable";
	protected static $storeClassVolatile  = "\\UUIDStorageVolatile";
	protected static $storeExceptionClass = "\\UUIDStorageException";
	protected static $exceptionClass      = "\\UUIDException";
}
class UUIDException extends JKingWeb\DrUUID\UUIDException {}
class UUIDStorageException extends UUIDException {}
class UUIDStorageVolatile extends JKingWeb\DrUUID\UUIDStorageVolatile implements UUIDStorage {}
class UUIDStorageStable extends JKingWeb\DrUUID\UUIDStorageStable implements UUIDStorage {
	protected static $storeExceptionClass = "\\UUIDStorageException";
}