<?php
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