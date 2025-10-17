<?php
declare(strict_types=1);

namespace JKingWeb\DrUUID;

class UUID {
    protected const MD5  = 3;
    protected const SHA1 = 5;
    protected const clearVer = 15;  // 00001111  Clears all bits of version byte with AND
    protected const clearVar = 63;  // 00111111  Clears all relevant bits of variant byte with AND
    protected const varRes   = 224; // 11100000  Variant reserved for future use
    protected const varMS    = 192; // 11000000  Microsft GUID variant
    protected const varRFC   = 128; // 10000000  The RFC 9562 variant (this variant)
    protected const varNCS   = 0;   // 00000000  The NCS compatibility variant
    protected const version1 = 16;  // 00010000
    protected const version3 = 48;  // 00110000
    protected const version4 = 64;  // 01000000
    protected const version5 = 80;  // 01010000
    protected const version6 = 96;  // 01100000
    protected const version7 = 112; // 01110000
    protected const version8 = 128; // 10000000
    protected const interval = "122192928000000000"; //  Time (in 100ns steps) between the start of the Gregorian and Unix epochs
    public const nsDNS  = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
    public const nsURL  = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';
    public const nsOID  = '6ba7b812-9dad-11d1-80b4-00c04fd430c8';
    public const nsX500 = '6ba7b814-9dad-11d1-80b4-00c04fd430c8';
    public const bigChoose = -1;
    public const bigNot    = 0;
    public const bigNative = 1;
    public const bigGMP    = 2;
    public const bigBC     = 3;
    public const bigSecLib = 4;
    public const randChoose  = -1;
    public const randPoor    = 0;
    public const randDev     = 1;
    public const randCAPICOM = 2;
    public const randOpenSSL = 3;
    public const randMcrypt  = 4;
    public const randNative  = 5;
    //static properties
    protected static $bignum              = self::bigChoose;
    protected static $storeClass          = UUIDStorageStable::class;
    /** @var \JKingWeb\DrUUID\UUIDStorage */
    protected static $store;
    //instance properties
    protected $bytes;
    protected $hex;
    protected $string;
    protected $urn;
    protected $version;
    protected $variant;
    protected $node;
    protected $time;
    
    public static function mint(int $ver = 7, ?string $node = null, ?string $ns = null): static {
        /* Create a new UUID based on provided data. */
        switch($ver) {
            case 1:
                return new static(static::mintTime());
            case 2:
                // Version 2 is not supported 
                throw new UUIDException("Version 2 is unsupported.",2);
            case 3:
                return new static(static::mintName(self::MD5, $node, $ns));
            case 4:
                return new static(static::mintRand());
            case 5:
                return new static(static::mintName(self::SHA1, $node, $ns));
            case 6:
                return new static(static::mintTime(true));
            case 7:
                return new static(static::mintTime7());
            case 8:
                return new static(static::mintCustom($node, $ns));
            default:
                throw new UUIDException("Selected version is invalid or unsupported.",1);
        }
    }

    public static function mintStr(int $ver = 7, ?string $node = null, ?string $ns = null): string {
        /* Create a new UUID based on provided data and output a string rather than an object. */
        switch($ver) {
            case 1:
                $uuid = static::mintTime();
                break;
            case 2:
                // Version 2 is not supported 
                throw new UUIDException("Version 2 is unsupported.",2);
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
                $uuid = static::mintTime(true);
                break;
            case 7:
                $uuid = static::mintTime7();
                break;
            case 8:
                $uuid = static::mintCustom($node, $ns);
            default:
                throw new UUIDException("Selected version is invalid or unsupported.",1);
        }
        return 
            bin2hex(substr($uuid,0,4))."-".
            bin2hex(substr($uuid,4,2))."-".
            bin2hex(substr($uuid,6,2))."-".
            bin2hex(substr($uuid,8,2))."-".
            bin2hex(substr($uuid,10,6));
    }

    public static function import($uuid): self {
        /* Import an existing UUID. */
        return ($uuid instanceof self) ? $uuid : new static(static::makeBin($uuid));
    }   

    public static function compare($a, $b): bool {
        /* Compares the binary representations of two UUIDs.
           The comparison will return true if they are bit-exact,
           or if neither is valid. */
        if (static::makeBin($a)==static::makeBin($b))
            return true;
        else
            return false;
    }
    
    protected static function seq(): string {
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
                    return null;
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
                        return null;

                }
            default:
                return null;
        }
    }

    protected function __construct(string $uuid) {
        if (strlen($uuid) != 16)
            throw new UUIDException("Input must be a valid UUID.",3);
        $this->bytes  = $uuid;
        // Optimize the most common use
        $this->string = 
            bin2hex(substr($uuid,0,4))."-".
            bin2hex(substr($uuid,4,2))."-".
            bin2hex(substr($uuid,6,2))."-".
            bin2hex(substr($uuid,8,2))."-".
            bin2hex(substr($uuid,10,6));
    }

    protected static function mintCustom(?string $data, ?string $ns): string {
        throw new UUIDException("Selected version is invalid or unsupported.",1);
    }

    protected static function mintTime(bool $ordered = false): string {
        /* Generates a Version 1 UUID.  
           These are derived from the time at which they were generated. */
        // Check for native 64-bit integer support
        if (static::$bignum == self::bigChoose)
            static::$bignum = (\PHP_INT_SIZE >= 8) ? self::bigNative : self::bigNot;
        // ensure a store is available
        if (static::$store === null) 
            static::$store = new UUIDStorageVolatile;
        // Get the current time
        $time = static::normalizeTime(static::now(), 7);
        // Get the node and sequence from storage
        $node = static::$store->getNode() ?? static::makeNode();
        $seq = static::$store->getSequence($time, $node);
        if ($seq === null) {
            $seq = static::seq();
            static::$store->setSequence($seq);
        }
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

    protected static function mintTime7(): string {
        /* Generates a Version 7 UUID.
           These are also time-based, but use a simple Unix timestamp
           with miliseconds. Since these are 48 bits in length, which
           fits within the integer precision of double-precision
           floating point numbers, they are easy to handle even on
           32-bit systems.
        */
        $time = static::normalizeTime(static::now(), 3);
        $time = base_convert($time, 10, 16);
        $time = pack("H*", str_pad($time, 12, "0", \STR_PAD_LEFT));
        // fill the rest of the UUID with random bytes
        $uuid = $time.static::randomBytes(10);
        // set variant and version
        $uuid[8] = chr(ord($uuid[8]) & self::clearVar | self::varRFC);
        $uuid[6] = chr(ord($uuid[6]) & self::clearVer | self::version7);
        return $uuid;
    }

    protected static function mintRand(): string {
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

    protected static function mintName(int $ver, ?string $node, ?string $ns): string {
        /* Generates a Version 3 or Version 5 UUID.
                    These are derived from a hash of a name and its namespace, in binary form. */
        if ($ver == 3)
        if (!$node)
            throw new UUIDException("A name-string is required for Version 3 or 5 UUIDs.",201);
        // if the namespace UUID isn't binary, make it so
        $ns = static::makeBin($ns);
        if (!$ns)
            throw new UUIDException("A valid UUID namespace is required for Version 3 or 5 UUIDs.",202);
        switch($ver) {
            case self::MD5: 
                $version = self::version3;
                $uuid = md5($ns.$node,true);
                break;
            case self::SHA1:
                $version = self::version5;
                $uuid = substr(sha1($ns.$node,true),0, 16);
                break;
        }
        // set variant
        $uuid[8] = chr(ord($uuid[8]) & self::clearVar | self::varRFC);
        // set version
        $uuid[6] = chr(ord($uuid[6]) & self::clearVer | $version);
        return ($uuid);
    }

    protected static function normalizeTime(string $time, int $precision): string {
        $time = explode(" ", $time);
        return $time[1].substr(str_pad($time[0], $precision + 2, "0", \STR_PAD_RIGHT),2,$precision);
    }

    protected static function buildTime($time): string {
        switch (static::$bignum) {
            case self::bigNative:
                $out = dechex($time + self::interval);
                break;
            case self::bigNot:
            case self::bigSecLib:
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
                $base = hexdec(str_repeat("f", (\PHP_INT_SIZE * 2) -1)) + 1;
                do {
                    $mod = bcmod($in,$base);
                    $in = bcdiv($in,$base,0);
                    $out = base_convert($mod, 10, 16).$out;
                } while($in > 0);
                break;
            default:
                throw new UUIDException("Bignum method not implemented.",901);
        }
        // convert to binary, padding to 8 bytes
        return pack("H*", str_pad($out, 16, "0", \STR_PAD_LEFT));
    }  

    protected static function decodeTimestamp(string $hex): string {
        /* Convrt a UUID timestamp (in hex notation) to 
           a Unix timestamp with microseconds. */
        // Check for native 64-bit integer support
        if (static::$bignum == self::bigChoose)
            static::$bignum = (\PHP_INT_SIZE >= 8) ? self::bigNative : self::bigNot;
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
                $time = "0";
                $mul = "1";
                $size = \PHP_INT_SIZE * 2 - 1;
                $max = hexdec(str_repeat("f", $size))+1;
                $hex = str_split(str_pad($hex, (int) ceil(strlen($hex) / $size) * $size, "0", \STR_PAD_LEFT), $size);
                do {
                    $chunk = (string) hexdec(array_pop($hex));
                    $time = bcadd($time, bcmul($chunk, $mul));
                    $mul = bcmul($max, $mul);
                } while (sizeof($hex));
                // And finally subtract the magic number to get the correct timestamp
                $time = bcsub($time, self::interval);
                break;
            case self::bigNot:
            case self::bigSecLib:
                $time = static::bigSub(static::bigDec($hex), self::interval);
                break;
            default:
                throw new UUIDException("Bignum method not implemented.",901);
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
                return false;
            else
                return pack("H*", $str);
    }

    protected static function makeNode(): string {
        $node = static::randomBytes(6);
        $node[0] = chr(ord($node[0]) | 1);
        return $node;
    }

    protected static function now(): string {
        return microtime();
    }

    protected static function randomBytes(int $bytes): string {
        return random_bytes($bytes);
    } 

    public static function initAccurate(): void {
        static::initBignum();
        if (!is_object(static::$store)) {
            try {
                call_user_func_array(array("self","initStorage"),func_get_args());
            } catch(\Exception $e) {
                throw new UUIDStorageException("Stable storage not available.", 2003, $e);
            }
        } else if (!(static::$store instanceof UUIDStorage)) {
            throw new UUIDStorageException("Storage is invalid.", 2004);
        }
    }

    public static function initBignum(?int $how = null): int {
        /* Check to see if PHP is running in a 32-bit environment and if so, 
           use GMP or BC Math if available. */
        if ($how === null) {
            if (static::$bignum != self::bigChoose) { // determination has already been made
                return static::$bignum;
            } else if (\PHP_INT_SIZE >= 8) {
                static::$bignum = self::bigNative;
            } else if (function_exists("gmp_add")) {
                static::$bignum = self::bigGMP;
            } else if (function_exists("bcadd")) {
                static::$bignum = self::bigBC;
            } else {
                static::$bignum = self::bigNot;
            } 
        } else {
            switch($how) {
                case self::bigChoose:
                    static::$bignum = $how;
                    return static::initBignum();
                case self::bigSecLib:
                case self::bigNot:
                    break;
                case self::bigNative:
                    if (\PHP_INT_SIZE < 8) 
                        throw new UUIDException("Bignum method is not available.", 801);
                    break;
                case self::bigGMP:
                    if (!function_exists("gmp_add"))
                        throw new UUIDException("Bignum method is not available.", 801);
                    break;
                case self::bigBC:
                    if (!function_exists("bcadd"))
                        throw new UUIDException("Bignum method is not available.", 801);
                    break;
                default:
                    throw new UUIDException("Bignum method not implemented.", 901);
            }
            static::$bignum = $how;
        }
        return static::$bignum;
    }

    public static function initStorage(?string $file = null): void {
        if (static::$storeClass == UUIDStorageStable::class) {
            try {static::$store = new UUIDStorageStable($file);}
            catch(\Exception $e) {throw new UUIDStorageException("Storage class could not be instantiated with supplied arguments.", 1003, $e);}
            return;
        }
        $store = new \ReflectionClass(static::$storeClass);
        $args = func_get_args();
        try {static::$store = $store->newInstanceArgs($args);} 
        catch(\Exception $e) {throw new UUIDStorageException("Storage class could not be instantiated with supplied arguments.", 1003, $e);}
    }

    public static function registerStorage(string $name): void {
        try {
            $store = new \ReflectionClass($name);
        } catch(\Exception $e) {
            throw new UUIDStorageException("Storage class does not exist.", 1001, $e);
        }
        if (!$store instanceof UUIDStorage)
            throw new UUIDStorageException("Storage class does not implement the UUIDStorage interface.", 1002);
        static::$storeClass = $name;
        if (func_num_args() > 1) {
            $args = func_get_args();
            array_shift($args);
            try {
                static::$store = $store->newInstanceArgs($args);
            } catch(\Exception $e) {
                throw new UUIDStorageException("Storage class could not be instantiated with supplied arguments.", 1003, $e);
            }
        }
    }

    protected static function bigAdd(string $a, string $b): string {
        $s = max(strlen($a), strlen($b));
        $a = str_pad($a, $s, "0", \STR_PAD_LEFT);
        $b = str_pad($b, $s, "0", \STR_PAD_LEFT);
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

    protected static function bigSub(string $a, string $b): string {
        $m = 1000000000;
        $s = max(strlen($a), strlen($b));
        $a = str_pad($a, $s, "0", \STR_PAD_LEFT);
        $b = str_pad($b, $s, "0", \STR_PAD_LEFT);
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
            $n = str_pad($nn, 9, "0", \STR_PAD_LEFT).$n;
        }
        return ltrim($n, "0");
    }
    protected static function bigHex(string $n): string {
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
            $h = str_pad(dechex($r), 6, "0", \STR_PAD_LEFT).$h;
            $n = ltrim($q, "0");
        }
        return ltrim($h, "0");
    }

    protected static function bigDec(string $h): string {
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
            $n = str_pad((string) hexdec($r), 8, "0", \STR_PAD_LEFT).$n;
            $h = ltrim($q, "0");
        }
        return ltrim($n, "0");
    }
}