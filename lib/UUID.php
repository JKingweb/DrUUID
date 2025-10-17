<?php
namespace JKingWeb\DrUUID;

class UUID {
	const MD5  = 3;
	const SHA1 = 5;
	const clearVer = 15;  // 00001111  Clears all bits of version byte with AND
	const clearVar = 63;  // 00111111  Clears all relevant bits of variant byte with AND
	const varRes   = 224; // 11100000  Variant reserved for future use
	const varMS    = 192; // 11000000  Microsft GUID variant
	const varRFC   = 128; // 10000000  The RFC 9562 variant (this variant)
	const varNCS   = 0;   // 00000000  The NCS compatibility variant
	const version1 = 16;  // 00010000
	const version3 = 48;  // 00110000
	const version4 = 64;  // 01000000
	const version5 = 80;  // 01010000
	const version6 = 96;  // 01100000
	const version7 = 112; // 01110000
	const version8 = 128; // 10000000
	const interval = "122192928000000000"; //  Time (in 100ns steps) between the start of the Gregorian and Unix epochs
	const nsDNS  = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
	const nsURL  = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';
	const nsOID  = '6ba7b812-9dad-11d1-80b4-00c04fd430c8';
	const nsX500 = '6ba7b814-9dad-11d1-80b4-00c04fd430c8';
	const bigChoose = -1;
	const bigNot    = 0;
	const bigNative = 1;
	const bigGMP    = 2;
	const bigBC     = 3;
	const bigSecLib = 4;
	const randChoose  = -1;
	const randPoor    = 0;
	const randDev     = 1;
	const randCAPICOM = 2;
	const randOpenSSL = 3;
	const randMcrypt  = 4;
	const randNative  = 5;
	//static properties
	protected static $randomFunc          = self::randChoose;
	protected static $randomSource        = NULL;
	protected static $bignum              = self::bigChoose;
	protected static $storeClass          = "\\JKingWeb\\DrUUID\\UUIDStorageStable";
	protected static $storeClassVolatile  = "\\JKingWeb\\DrUUID\\UUIDStorageVolatile";
	protected static $storeExceptionClass = "\\JKingWeb\\DrUUID\\UUIDStorageException";
	protected static $exceptionClass      = "\\JKingWeb\\DrUUID\\UUIDException";
	protected static $store               = NULL;
	protected static $secLib              = NULL;
	//instance properties
	protected $bytes;
	protected $hex;
	protected $string;
	protected $urn;
	protected $version;
	protected $variant;
	protected $node;
	protected $time;
	
	public static function mint($ver = 1, $node = NULL, $ns = NULL, $time = NULL) {
		/* Create a new UUID based on provided data. */
		switch((int) $ver) {
			case 1:
				return new static(static::mintTime($node, $ns, $time));
			case 2:
				// Version 2 is not supported 
				throw new static::$exceptionClass("Version 2 is unsupported.",2);
			case 3:
				return new static(static::mintName(self::MD5, $node, $ns));
			case 4:
				return new static(static::mintRand());
			case 5:
				return new static(static::mintName(self::SHA1, $node, $ns));
			case 6:
				return new static(static::mintTime($node, $ns, $time, true));
			case 7:
				return new static(static::mintTime7($time));
			case 8:
				return new static(static::mintCustom($node, $ns));
			default:
				throw new static::$exceptionClass("Selected version is invalid or unsupported.",1);
		}
	}

	public static function mintStr($ver = 1, $node = NULL, $ns = NULL, $time = NULL) {
		/* If a randomness source hasn't been chosen, use the lowest common denominator. */
		if (static::$randomFunc == self::randChoose) static::$randomFunc = self::randPoor;
		/* Create a new UUID based on provided data and output a string rather than an object. */
		switch((int) $ver) {
			case 1:
				$uuid = static::mintTime($node, $ns, $time);
				break;
			case 2:
				// Version 2 is not supported 
				throw new static::$exceptionClass("Version 2 is unsupported.",2);
				break;
			case 3:
				$uuid = static::mintName(self::MD5, $node, $ns);
				break;
			case 4:
				$uuid = static::mintRand();
				break;
			case 5:
				$uuid = static::mintName(self::SHA1, $node, $ns);
				break;
			case 6:
				$uuid = static::mintTime($node, $ns, $time, true);
				break;
			case 7:
				$uuid = static::mintTime7($time);
				break;
			case 8:
				$uuid = static::mintCustom($node, $ns);
			default:
				throw new static::$exceptionClass("Selected version is invalid or unsupported.",1);
		}
		return 
			bin2hex(substr($uuid,0,4))."-".
			bin2hex(substr($uuid,4,2))."-".
			bin2hex(substr($uuid,6,2))."-".
			bin2hex(substr($uuid,8,2))."-".
			bin2hex(substr($uuid,10,6));
	}

	public static function import($uuid) {
		/* Import an existing UUID. */
		return ($uuid instanceof self) ? $uuid : new static(static::makeBin($uuid));
	}   

	public static function compare($a, $b) {
		/* Compares the binary representations of two UUIDs.
		   The comparison will return true if they are bit-exact,
		   or if neither is valid. */
		if (static::makeBin($a)==static::makeBin($b))
			return TRUE;
		else
			return FALSE;
	}
	
	public static function seq() {
		/* Generate a random clock sequence; this is just two random bytes with the two most significant bits set to zero. */
		$seq = static::randomBytes(2);
		$seq[0] = chr(ord($seq[0]) & self::clearVar);
		return $seq;
	}

	public function __toString() {
		return $this->string;
	}

	public function __get($var) {
		switch($var) {
			case "bytes":
				return $this->bytes;
			case "hex":
				return bin2hex($this->bytes);
			case "string":
				return $this->string;
			case "urn":
				return "urn:uuid:".$this->string;
			case "version":
				return ord($this->bytes[6]) >> 4;
			case "variant":
				$byte = ord($this->bytes[8]);
				if ($byte >= self::varRes)
					return 3;
				if ($byte >= self::varMS)
					return 2;
				if ($byte >= self::varRFC)
					return 1;
				else
					return 0;
			case "node":
				if (ord($this->bytes[6])>>4==1)
					return bin2hex(strrev(substr($this->bytes,10)));
				else
					return NULL;
			case "time":
				switch (ord($this->bytes[6])>>4) {
					case 1:
						// Restore contiguous big-endian byte order
						$time = bin2hex($this->bytes[6].$this->bytes[7].$this->bytes[4].$this->bytes[5].substr($this->bytes, 0, 4));
						// Clear version flag
						$time[0] = "0";
						// Decode the hex digits and return a fixed-precision string
						return static::decodeTimestamp($time);
					case 6:
						// Remove the version nybble and pad to 64 bits
						$time = bin2hex(substr($this->bytes, 0, 8));
						$time = "0".substr($time, 0, 12).substr($time, 13);
						// Decode the hex digits and return a fixed-precision string
						return static::decodeTimestamp($time);
					case 7:
						// Convert the time to decimal
						$time = bin2hex(substr($this->bytes, 0, 6));
						$time = base_convert($time, 16, 10);
						$time = substr($time, 0, strlen($time) - 3).".".substr($time, -3);
						return $time;
					default:
						return NULL;

				}
			default:
				return NULL;
		}
	}

	protected function __construct($uuid) {
		if (strlen($uuid) != 16)
			throw new static::$exceptionClass("Input must be a valid UUID.",3);
		$this->bytes  = $uuid;
		// Optimize the most common use
		$this->string = 
			bin2hex(substr($uuid,0,4))."-".
			bin2hex(substr($uuid,4,2))."-".
			bin2hex(substr($uuid,6,2))."-".
			bin2hex(substr($uuid,8,2))."-".
			bin2hex(substr($uuid,10,6));
	}

	protected static function mintCustom($dnode, $ns) {
		throw new static::$exceptionClass("Selected version is invalid or unsupported.",1);
	}

	protected static function mintTime($node = NULL, $seq = NULL, $time = NULL, $ordered = FALSE) {
		/* Generates a Version 1 UUID.  
		   These are derived from the time at which they were generated. */
		// Check for native 64-bit integer support
		if (static::$bignum == self::bigChoose)
			static::$bignum = (PHP_INT_SIZE >= 8) ? self::bigNative : self::bigNot;
		// ensure a store is available
		if (static::$store === NULL) 
			static::$store = new static::$storeClassVolatile;
		// check any input for correctness and communicate with the store where appropriate
		list($node, $seq, $time) = static::checkTimeInput($node, $seq, $time);
		// construct a 60-bit timestamp, padded to 64 bits
		$time = static::buildTime($time);
		if ($ordered) {
			$uuid = bin2hex($time);
			// 0x6 is the value of the version field
			$uuid = hex2bin(substr($uuid, 1, 12)."6".substr($uuid, 13));
		} else {
			// Reorder bytes to their proper locations in the UUID
			$uuid  = $time[4].$time[5].$time[6].$time[7].$time[2].$time[3].$time[0].$time[1];
			// set version
			$uuid[6] = chr(ord($uuid[6]) & self::clearVer | self::version1);
		}
		// Add the clock sequence
		$uuid .= $seq;
		// set variant
		$uuid[8] = chr(ord($uuid[8]) & self::clearVar | self::varRFC);
		// Set the final 'node' parameter, a MAC address
		$uuid .= $node;
		return $uuid;
	}

	protected static function mintTime7($time = NULL) {
		/* Generates a Version 7 UUID.
		   These are also time-based, but use a simple Unix timestamp
		   with miliseconds. Since these are 48 bits in length, which
		   fits within the integer precision of double-precision
		   floating point numbers, they are easy to handle even on
		   32-bit systems.
		*/
		if ($time === null) {
			$time = microtime();
		}
		$time = static::normalizeTime($time, 3);
		$time = base_convert($time, 10, 16);
		$time = pack("H*", str_pad($time, 12, "0", STR_PAD_LEFT));
		// fill the rest of the UUID with random bytes
		$uuid = $time.static::randomBytes(10);
		// set variant and version
		$uuid[8] = chr(ord($uuid[8]) & self::clearVar | self::varRFC);
		$uuid[6] = chr(ord($uuid[6]) & self::clearVer | self::version7);
		return $uuid;
	}

	protected static function mintRand() {
		/* Generate a Version 4 UUID.  
		   These are derived solely from random numbers. */
		// generate random fields
		$uuid = static::randomBytes(16);
		// set variant
		$uuid[8] = chr(ord($uuid[8]) & self::clearVar | self::varRFC);
		// set version
		$uuid[6] = chr(ord($uuid[6]) & self::clearVer | self::version4);
		return $uuid;
	}

	protected static function mintName($ver, $node, $ns) {
		/* Generates a Version 3 or Version 5 UUID.
					These are derived from a hash of a name and its namespace, in binary form. */
		if ($ver == 3)
		if (!$node)
			throw new static::$exceptionClass("A name-string is required for Version 3 or 5 UUIDs.",201);
		// if the namespace UUID isn't binary, make it so
		$ns = static::makeBin($ns);
		if (!$ns)
			throw new static::$exceptionClass("A valid UUID namespace is required for Version 3 or 5 UUIDs.",202);
		switch($ver) {
			case self::MD5: 
				$version = self::version3;
				$uuid = md5($ns.$node,1);
				break;
			case self::SHA1:
				$version = self::version5;
				$uuid = substr(sha1($ns.$node,1),0, 16);
				break;
		}
		// set variant
		$uuid[8] = chr(ord($uuid[8]) & self::clearVar | self::varRFC);
		// set version
		$uuid[6] = chr(ord($uuid[6]) & self::clearVer | $version);
		return ($uuid);
	}

	protected static function CheckTimeInput($node, $seq, $time) {
		/* If no timestamp has been specified, generate one.
		   Note that this will never be more accurate than to 
		   the microsecond, whereas UUID timestamps are measured in 100ns steps. */
		$time = ($time !== NULL) ? static::normalizeTime($time) : static::normalizeTime(microtime());
		/* If a node ID is supplied, use it and keep it in the store; if none is 
		   supplied, get it from the store or generate it if none is stored. */
		if ($node === NULL) {
			$node = static::$store->getNode();
			if (!$node) {
				$node = static::randomBytes(6);
				$node[0] = pack("C", ord($node[0]) | 1);
			}
		} else {
			$node = static::makeNode($node);
			if (!$node)
				throw new static::$exceptionClass("Node must be a valid MAC address.", 101);
		}
		// Do a sanity check on clock sequence if one is provided
		if ($seq !== NULL && strlen($seq) != 2)
			throw new UUIDException("Clock sequence must be a two-byte binary string.",102);
		// If one is not provided, check stable/volatile storage for a valid clock sequence
		if ($seq === NULL)
			$seq = static::$store->getSequence($time, $node);
		// Generate a random clock sequence if one is not available
		if (!$seq) {
			$seq = static::seq();
			static::$store->setSequence($seq);
		}
		static::$store->setTimestamp($time);
		return array($node, $seq, $time);
	}

	protected static function normalizeTime($time, $precision = 7) {
		/* Returns a string representation of the 
		   time since the Unix epoch, with variable precision. */
		if(is_a($time, "DateTimeInterface") || is_a($time, "DateTime"))
			return $time->format("U").substr(str_pad($time->format("u"), $precision, "0", STR_PAD_RIGHT),0,$precision);
		switch(gettype($time)) {
			case "string":
				$time = explode(" ", $time);
				if(sizeof($time) != 2) throw new static::$exceptionClass("Time input was of an unexpected format.",103);
				return $time[1].substr(str_pad($time[0], $precision + 2, "0", STR_PAD_RIGHT),2,$precision);
			case "integer": // assume a second-precision timestamp
				return $time.str_repeat("0", $precision);
			case "double":
				$time = sprintf("%F", $time);
				$time = explode(".", $time);
				return $time[0].substr(str_pad($time[1], $precision, "0", STR_PAD_RIGHT),0,$precision);
			default:
				throw new static::$exceptionClass("Time input was of an unexpected format.",103);
		}
	}

	protected static function buildTime($time) {
		switch (static::$bignum) {
			case self::bigNative:
				$out = dechex($time + self::interval);
				break;
			case self::bigNot:
				// add the magic interval
				$out = static::bigAdd($time, self::interval);
				// convert to hexdecimal notation, big-endian
				$out = static::bigHex($out);
				break;
			case self::bigGMP:
				$out = gmp_strval(gmp_add($time, self::interval), 16);
				break;
			case self::bigBC:
				$in = bcadd($time, self::interval, 0);
				$$out = "";
				/* BC Math does not have a native equivalent of base_convert(), 
				   so we have to fake it.  Chunking the number to as many 
				   nybbles as PHP can handle in an integer speeds things up lots. */
				$base = (int) hexdec(str_repeat("f", (PHP_INT_SIZE * 2) -1)) + 1;
				do {
					$mod = (int) bcmod($in,$base);
					$in = bcdiv($in,$base,0);
					$out = base_convert($mod, 10, 16).$out;
				} while($in > 0);
				break;
			case self::bigSecLib:
				$out = new static::$secLib($time);
				$out = $out->add(new static::$secLib(self::interval));
				$out = $out->toHex();
				break;
			default:
				throw new static::$exceptionClass("Bignum method not implemented.",901);
		}
		// convert to binary, padding to 8 bytes
		return pack("H*", str_pad($out, 16, "0", STR_PAD_LEFT));
	}  

	protected static function decodeTimestamp($hex) {
		/* Convrt a UUID timestamp (in hex notation) to 
		   a Unix timestamp with microseconds. */
		// Check for native 64-bit integer support
		if (static::$bignum == self::bigChoose)
			static::$bignum = (PHP_INT_SIZE >= 8) ? self::bigNative : self::bigNot;
		switch(static::$bignum) {
			case self::bigNative:
				$time = hexdec($hex) - self::interval; 
				break;
			case self::bigGMP:
				$time = gmp_strval(gmp_sub("0x".$hex, self::interval)); 
				break;
			case self::bigBC:
				/* BC Math does not natively handle hexadecimal input, 
				   so we must convert to decimal in safe-sized chunks. */
				$time = 0;
				$mul = 1;
				$size = PHP_INT_SIZE * 2 - 1;
				$max = hexdec(str_repeat("f", $size))+1;
				$hex = str_split(str_pad($hex, ceil(strlen($hex) / $size) * $size, 0, STR_PAD_LEFT), $size);
				do {
					$chunk = hexdec(array_pop($hex));
					$time = bcadd($time, bcmul($chunk, $mul));
					$mul = bcmul($max, $mul);
				} while (sizeof($hex));
				// And finally subtract the magic number to get the correct timestamp
				$time = bcsub($time, self::interval);
				break;
			case self::bigSecLib:
				$time = new static::$secLib($hex, 16);
				$time = $time->subtract(new static::$secLib(self::interval));
				$time = $time->toString();
				break;
			case self::bigNot:
				$time = static::bigSub(static::bigDec($hex), self::interval);
				break;
			default:
				throw new static::$exceptionClass("Bignum method not implemented.",901);
		}
		return substr($time,0,strlen($time)-7).".".substr($time,strlen($time)-7);
	}

	protected static function makeBin($str) {
		/* Ensure that an input string is a UUID.
		   Returns binary representation, or false on failure. */
		$len = 16;
		if ($str instanceof self)
			return $str->bytes;
		if (strlen($str)==$len)
			return $str;
		else
			$str = preg_replace("/^urn:uuid:/is", "", $str); // strip URN scheme and namespace
			$str = preg_replace("/[^a-f0-9]/is", "", $str);  // strip non-hex characters
			if (strlen($str) != ($len * 2))
				return FALSE;
			else
				return pack("H*", $str);
	}

	protected static function makeNode($str) {
		/* Parse a string to see if it's a MAC address.
		   If it's six bytes, don't touch it; if it's hex, reverse bytes */
		$len = 6;
		if (strlen($str)==$len)
			return $str;
		else
			$str = preg_replace("/[^a-f0-9]/is", "", $str);  // strip non-hex characters
			if (strlen($str) != ($len * 2))
				return FALSE;
			else
				return pack("H*", $str);
	}

	public static function randomBytes($bytes) {
		switch (static::$randomFunc) {
			case self::randChoose:
			case self::randPoor:
				/* Get the specified number of random bytes, using mt_rand(). */
				$rand = "";
				for ($a = 0; $a < $bytes; $a++) {
					$rand .= chr(mt_rand(0, 255));
				} 
				return $rand;
			case self::randNative:
				/* Get the specified number of bytes from the PHP core. 
				   This is available since PHP 7. */
				return random_bytes($bytes);
			case self::randDev:
				/* Get the specified number of random bytes using a file handle 
				   previously opened with UUID::initRandom(). */
				return fread(static::$randomSource, $bytes);
			case self::randOpenSSL:
				/* Get the specified number of bytes from OpenSSL.
				   This is available since PHP 5.3. */
				return openssl_random_pseudo_bytes($bytes);
			case self::randMcrypt:
				/* Get the specified number of random bytes via Mcrypt. */
				return mcrypt_create_iv($bytes);
			case self::randCAPICOM:
				/* Get the specified number of random bytes using Windows'
				   randomness source via a COM object previously created by UUID::initRandom().
				   Straight binary mysteriously doesn't work, hence the base64. */
				return base64_decode(static::$randomSource->GetRandom($bytes,0));
			default:
				throw new static::$exceptionClass("Randomness source not implemented.",902);
		}
	} 

	public static function initAccurate() {
		$big = static::initBignum();
		$rand = static::initRandom();
		if ($rand == self::randPoor)
			throw new static::$exceptionClass("Secure random number generator is not available.",2002);
		if (!is_object(static::$store)) {
			try {
				call_user_func_array(array("self","initStorage"),func_get_args());
			} catch(\Exception $e) {
				throw new static::$storeExceptionClass("Stable storage not available.", 2003, $e);
			}
		} else if (!(static::$store instanceof UUIDStorage)) {
			throw new static::$storeExceptionClass("Storage is invalid.", 2004);
		}
	}

	public static function initRandom($how = NULL) {
		/* Look for a system-provided source of randomness, which is usually crytographically secure.
		   /dev/urandom is tried first because tests suggest it is faster than other options. */
		if ($how === NULL) {
			if (static::$randomFunc != self::randChoose)
				return static::$randomFunc;
			else if (function_exists('random_bytes'))
				$how = self::randNative;
			else if (function_exists('openssl_random_pseudo_bytes'))
				$how = self::randOpenSSL;
			else if (function_exists('mcrypt_create_iv'))
				$how = self::randMcrypt;
			else if (is_readable('/dev/urandom')) 
				$how = self::randDev;
			else 
				$how = self::randCAPICOM;
			try {
				static::initRandom($how);
			} catch(\Exception $e) {
				static::$randomFunc = self::randPoor;
			}
		} else {
			$source = NULL;
			switch($how) {
				case self::randChoose:
					static::$randomFunc = $how;
					return static::initRandom();
				case self::randPoor:
					static::$randomFunc = $how;
					break;
				case self::randNative:
					if (!function_exists('random_bytes'))
						throw new static::$exceptionClass("Randomness source is not available.", 802);
					break;
			case self::randDev:
					$source = @fopen('/dev/urandom', 'rb');
					if (!$source) 
						throw new static::$exceptionClass("Randomness source is not available.", 802);
					break;
				case self::randOpenSSL:
					if (!function_exists('openssl_random_pseudo_bytes'))
						throw new static::$exceptionClass("Randomness source is not available.", 802);
					break;
				case self::randMcrypt:
					if (!function_exists('mcrypt_create_iv'))
						throw new static::$exceptionClass("Randomness source is not available.", 802);
					break;
				case self::randCAPICOM: // Only available in Windows XP and earlier. See http://msdn.microsoft.com/en-us/library/aa388182(VS.85).aspx
					if (!class_exists('COM', 0))
						throw new static::$exceptionClass("Randomness source is not available.", 802);
					try {$source = new \COM('CAPICOM.Utilities.1');}
					catch(\Exception $e) {throw new static::$exceptionClass("Randomness source is not available.", 802, $e);}
					break;
				default:
					throw new static::$exceptionClass("Randomness source not implemented.",902);
			}
			static::$randomSource = $source;
			static::$randomFunc = $how;
		}
		return static::$randomFunc;
	}

	public static function initBignum($how = NULL) {
		/* Check to see if PHP is running in a 32-bit environment and if so, 
		   use GMP or BC Math if available. */
		if ($how === NULL) {
			if (static::$bignum != self::bigChoose) { // determination has already been made
				return static::$bignum;
			} else if (PHP_INT_SIZE >= 8) {
				static::$bignum = self::bigNative;
			} else if (function_exists("gmp_add")) {
				static::$bignum = self::bigGMP;
			} else if (function_exists("bcadd")) {
				static::$bignum = self::bigBC;
			} else if (@class_exists("phpseclib\\Math\\BigInteger")) { // phpseclib v2.x
				static::$bignum = self::bigSecLib;
				static::$secLib = "\\phpseclib\\Math\\BigInteger";
			} else if (@class_exists("Math_BigInteger")) { // phpseclib v1.x
				static::$bignum = self::bigSecLib;
				static::$secLib = "\\Math_BigInteger";
			} else {
				static::$bignum = self::bigNot;
			} 
		} else {
			switch($how) {
				case self::bigChoose:
					static::$bignum = $how;
					return static::initBignum();
				case self::bigNot:
					break;
				case self::bigNative:
					if (PHP_INT_SIZE < 8) 
						throw new static::$exceptionClass("Bignum method is not available.", 801);
					break;
				case self::bigGMP:
					if (!function_exists("gmp_add"))
						throw new static::$exceptionClass("Bignum method is not available.", 801);
					break;
				case self::bigBC:
					if (!function_exists("bcadd"))
						throw new static::$exceptionClass("Bignum method is not available.", 801);
					break;
				case self::bigSecLib:
					if (class_exists("phpseclib\\Math\\BigInteger", 0)) //v2.x
						static::$secLib = "\\phpseclib\Math\\BigInteger";
					else if (class_exists("Math_BigInteger", 0)) //v1.x
						static::$secLib = "\\Math_BigInteger";
					else
						throw new static::$exceptionClass("Bignum method is not available.", 801);
					break;
				default:
					throw new static::$exceptionClass("Bignum method not implemented.", 901);
			}
			static::$bignum = $how;
		}
		return static::$bignum;
	}

	public static function initStorage($file = NULL) {
		if (static::$storeClass == "\\JKingWeb\\DrUUID\\UUIDStorageStable") {
			try {static::$store = new UUIDStorageStable($file);}
			catch(\Exception $e) {throw new static::$storeExceptionClass("Storage class could not be instantiated with supplied arguments.", 1003, $e);}
			return;
		} else if (static::$storeClass == "UUIDStorageStable") {
			try {static::$store = new \UUIDStorageStable($file);}
			catch(\Exception $e) {throw new static::$storeExceptionClass("Storage class could not be instantiated with supplied arguments.", 1003, $e);}
			return;
		}
		$store = new \ReflectionClass(static::$storeClass);
		$args = func_get_args();
		try {static::$store = $store->newInstanceArgs($args);} 
		catch(\Exception $e) {throw new static::$storeExceptionClass("Storage class could not be instantiated with supplied arguments.", 1003, $e);}
	}

	public static function registerStorage($name) {
		try {
			$store = new \ReflectionClass($name);
		} catch(\Exception $e) {
			throw new static::$storeExceptionClass("Storage class does not exist.", 1001, $e);
		}
		if (array_search("JKingWeb\\DrUUID\\UUIDStorage", $store->getInterfaceNames()) === FALSE)
			throw new static::$storeExceptionClass("Storage class does not implement the UUIDStorage interface.", 1002);
		static::$storeClass = $name;
		if (func_num_args() > 1) {
			$args = func_get_args();
			array_shift($args);
			try {
				static::$store = $store->newInstanceArgs($args);
			} catch(\Exception $e) {
				throw new static::$storeExceptionClass("Storage class could not be instantiated with supplied arguments.", 1003, $e);
			}
		}
	}

    protected static function bigAdd($a, $b) {
        $s = max(strlen($a), strlen($b));
        $a = str_pad($a, $s, "0", STR_PAD_LEFT);
        $b = str_pad($b, $s, "0", STR_PAD_LEFT);
        $c = 0;
        $n = "";
        for ($i = $s - 9; $i > -9; $i -= 9) {
            $ss = $i < 0 ? $i + 9 : 9;
            $aa = substr($a, max(0, $i), $ss);
            $bb = substr($b, max(0, $i), $ss);
            $n = (($aa + $bb + $c) % 1000000000).$n;
            $c = intdiv($aa + $bb + $c, 1000000000);
        }
        if ($c) {
            $n = $c.$n;
        }
        return $n;
    }

    protected static function bigSub($a, $b) {
        $m = 1000000000;
        $s = max(strlen($a), strlen($b));
        $a = str_pad($a, $s, "0", STR_PAD_LEFT);
        $b = str_pad($b, $s, "0", STR_PAD_LEFT);
        $c = 0;
        $n = "";
        for ($i = $s - 9; $i > -9; $i -= 9) {
            $ss = $i < 0 ? $i + 9 : 9;
            $aa = substr($a, max(0, $i), $ss);
            $bb = substr($b, max(0, $i), $ss);
            $nn = $aa - $bb - $c;
            if ($nn < 0) {
                $nn = $m + $nn;
                $c = 1;
            } else {
                $c = 0;
            }
            $n = str_pad($nn, 9, "0", STR_PAD_LEFT).$n;
        }
        return ltrim($n, "0");
    }
    protected static function bigHex($n) {
        $h = "";
        $n = (string) $n;
        $d = (string) (2**24);
        while ($n) {
            $s = strlen($n);
            $q = "";
            $r = 0;
            $i = 0;
            do {
                $nn = $r.$n[$i++];
                while ($nn < $d && $i < $s) {
                    $nn .= $n[$i++];
                    $q .= "0";
                }
                $qq = intdiv((int) $nn, (int) $d);
                $q .= $qq;
                $r = (int) $nn % (int) $d;
            } while ($i < $s);
            $h = str_pad(dechex($r), 6, "0", STR_PAD_LEFT).$h;
            $n = ltrim($q, "0");
        }
        return ltrim($h, "0");
    }

    protected static function bigDec($h) {
        $n = "";
        $d = 100000000;
        while ($h) {
            $s = strlen($h);
            $q = "";
            $r = "";
            $i = 0;
            do {
                $hh = $r.$h[$i++];
                while (hexdec($hh) < $d && $i < $s) {
                    $hh .= $h[$i++];
                    $q .= "0";
                }
                $qq = intdiv(hexdec($hh), $d);
                $q .= dechex($qq);
                $r = dechex(hexdec($hh) % $d);
            } while ($i < $s);
            $n = str_pad(hexdec($r), 8, "0", STR_PAD_LEFT).$n;
            $h = ltrim($q, "0");
        }
        return ltrim($n, "0");
    }

}