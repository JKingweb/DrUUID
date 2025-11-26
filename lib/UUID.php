<?php
declare(strict_types=1);

namespace JKingWeb\DrUUID;

/**
 * @property-read string $bytes The binary representation of the UUID
 * @property-read string $hex The bare hexadecimal representation of the UUID. Digits are always lowercase
 * @property-read string $string The canonical string representation of the UUID, with dashes. Digits are always lowercase
 * @property-read string $urn The URN representation of the UUID
 * @property-read int $variant The variant of the UUID. For RFC 9562 UUIDs this is always 1
 * @property-read int|null $version The version of the UUID. For RFC 9562 UUIDs this is one of 1, 3, 4, 5, 6, 7, or 8
 * @property-read string|null $node The node (a MAC address), available in Version 1 and Version 6 UUIDs
 * @property-read string|null $time The time at which the UUID was generated, as a Unix timestamp with subsecond precision. Available in Version 1 and Version 6 UUIDs (with a sub-second precision of seven digits) and Version 7 UUIDs (with a sub-second precision of three digits)
 */
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
    protected const bigChoose = -1;
    protected const bigNot    = 0;
    protected const bigNative = 1;
    protected const bigGMP    = 2;
    protected const bigBC     = 3;
    protected const interval = "122192928000000000"; //  Time (in 100ns steps) between the start of the Gregorian and Unix epochs
    public const nsDNS  = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
    public const nsURL  = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';
    public const nsOID  = '6ba7b812-9dad-11d1-80b4-00c04fd430c8';
    public const nsX500 = '6ba7b814-9dad-11d1-80b4-00c04fd430c8';
    protected static $bignum = self::bigChoose;
    /** @var \JKingWeb\DrUUID\UUIDStorage */
    protected static $store;
    protected $bytes;
    protected $hex;
    protected $string;
    protected $urn;
    protected $version;
    protected $variant;
    protected $node;
    protected $time;

    /** Generates a UUID object of the requested type
     *
     * The $ver argument may be any of the following:
     *
     * - 1: Time-based, but does not sort by time. Deprecated in favour of Version 7
     * - 3: MD5 hash-based. Deprecated in favour of Version 5
     * - 4: Random except for structural information
     * - 5: SHA-1 hash-based
     * - 6: A variant of Version 1 which sorts by time. Deprecated in favour of Version 7
     * - 7: Time-based, and simpler to produce than the other time-based options
     *
     * The $name and $namespace are both required for Version 3 and 5 UUIDs. See [Section 6.6 of RFC 9562](https://www.rfc-editor.org/rfc/rfc9562#name-namespace-id-usage-and-allo) for requirements and recommendations related to namespace selection
     *
     * @param int $ver The type of UUID to generate
     * @param ?string $name The name to hash, for Version 3 or 5 UUIDs
     * @param UUID|string|null $namespace The namespace containing the $name, for Version 3 or 5 UUIDs
     */
    public static function mint(int $ver = 7, ?string $name = null, $namespace = null): static {
        switch($ver) {
            case 1:
                return new static(static::mintTime());
            case 3:
                return new static(static::mintName(self::MD5, $name, $namespace));
            case 4:
                return new static(static::mintRand());
            case 5:
                return new static(static::mintName(self::SHA1, $name, $namespace));
            case 6:
                return new static(static::mintTime(true));
            case 7:
                return new static(static::mintTime7());
            case 8:
                return new static(static::mintCustom($name, $namespace));
            default:
                throw new \InvalidArgumentException("Version $ver UUIDs are not supported.");
        }
    }

    /** Generates a UUID of the requested type and returns its canonical string representation
     *
     * The $ver argument may be any of the following:
     *
     * - 1: Time-based, but does not sort by time. Deprecated in favour of Version 7
     * - 3: MD5 hash-based. Deprecated in favour of Version 5
     * - 4: Random except for structural information
     * - 5: SHA-1 hash-based
     * - 6: A variant of Version 1 which sorts by time. Deprecated in favour of Version 7
     * - 7: Time-based, and simpler to produce than the other time-based options
     *
     * The $name and $namespace are both required for Version 3 and 5 UUIDs. See [Section 6.6 of RFC 9562](https://www.rfc-editor.org/rfc/rfc9562#name-namespace-id-usage-and-allo) for requirements and recommendations related to namespace selection
     *
     * @param int $ver The type of UUID to generate
     * @param ?string $name The name to hash, for Version 3 or 5 UUIDs
     * @param UUID|string|null $namespace The namespace containing the $name, for Version 3 or 5 UUIDs
     */
    public static function mintStr(int $ver = 7, ?string $name = null, $namespace = null): string {
        switch($ver) {
            case 1:
                $uuid = static::mintTime();
                break;
            case 3:
                $uuid = static::mintName(self::MD5, $name, $namespace);
                break;
            case 4:
                $uuid = static::mintRand();
                break;
            case 5:
                $uuid = static::mintName(self::SHA1, $name, $namespace);
                break;
            case 6:
                $uuid = static::mintTime(true);
                break;
            case 7:
                $uuid = static::mintTime7();
                break;
            case 8:
                $uuid = static::mintCustom($name, $namespace);
            default:
                throw new \InvalidArgumentException("Version $ver UUIDs are not supported.");
        }
        return
            bin2hex(substr($uuid, 0, 4))."-".
            bin2hex(substr($uuid, 4, 2))."-".
            bin2hex(substr($uuid, 6, 2))."-".
            bin2hex(substr($uuid, 8, 2))."-".
            bin2hex(substr($uuid, 10, 6));
    }

    /** Converts a UUID string into a UUID object
     *
     * This can be used to extract data from the UUID, or to easily convert to a different representation.
     *
     * @param string $uuid The UUID to import. This can be in canonical form, as a binary string, as an URN, or as a string of hexadecimal digits
     * @return self|false
     */
    public static function import(string $uuid) {
        $out = static::makeBin($uuid);
        if (!$out) {
            return false;
        }
        return new static($out);
    }

    /** Compares two UUIDs of arbitrary representation for equality
     *
     * The two UUIDs can be a UUID object, a canonical string, a binary string, or a string of hexadecimal digits.
     * 
     * This functiion will return null if either argument cannot be parsed as a UUID
     *
     * @param static|string $a The first UUID to compare
     * @param static|string $b The second UUID to compare
     */
    public static function compare($a, $b): ?bool {
        $a = static::makeBin($a);
        $b = static::makeBin($b);
        if (!$a || !$b) {
            return null;
        }
        return $a === $b;
    }

    /** Generates a random clock sequence
     *
     * This is just two random bytes with the two most significant bits set to zero.
     */
    protected static function seq(): string {
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
                return $this->__get("variant") === 1 ? ord($this->bytes[6]) >> 4 : null;
            case "variant":
                $byte = ord($this->bytes[8]);
                if ($byte >= self::varRes) {
                    return 3;
                } elseif ($byte >= self::varMS) {
                    return 2;
                } elseif ($byte >= self::varRFC) {
                    return 1;
                }
                return 0;
            case "node":
                if ($this->__get("variant") !== 1) {
                    return null;
                }
                switch (ord($this->bytes[6])>>4) {
                    case 1:
                    case 6:
                        return bin2hex(substr($this->bytes, 10));
                    default:
                        return null;
                }
            case "time":
                if ($this->__get("variant") !== 1) {
                    return null;
                }
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
                        $time = str_pad(base_convert($time, 16, 10), 4, "0", \STR_PAD_LEFT);
                        $time = substr($time, 0, strlen($time) - 3).".".substr($time, -3);
                        return $time;
                    default:
                        return null;
                }
            default:
                return null;
        }
    }

    /** Instructs DrUUID to use an alternate state-storage engine for Version 1 and Version 6 UUIDs
     * 
     * By default DrUUID only stores the required state for optimal uniqueness
     * (the node, the clock sequence, and the last time at which a UUID was
     * generated) in memory. If the application is using Version 1 or Version 6
     * UUIDs and is storing its state to disk anyway, it can make use of an
     * implementation of the UUID interface with this library.
    */
    public static function registerStorage(UUIDStorage $store): void {
        static::$store = $store;
    }

    protected function __construct(string $uuid) {
        assert(strlen($uuid) === 16, new \InvalidArgumentException("Input must be a valid UUID."));
        $this->bytes  = $uuid;
        // Optimize the most common use
        $this->string =
            bin2hex(substr($uuid, 0, 4))."-".
            bin2hex(substr($uuid, 4, 2))."-".
            bin2hex(substr($uuid, 6, 2))."-".
            bin2hex(substr($uuid, 8, 2))."-".
            bin2hex(substr($uuid, 10, 6));
    }

    /** A stub for implementing Version 8 UUID generation */
    protected static function mintCustom(?string $data, ?string $ns): string {
        throw new \InvalidArgumentException("Version 8 UUIDs are not supported.");
    }

    /** Generates a version 1 or Version 6 UUID
     * 
     * @param bool $ordered Whether to produce a Version 6 UUID, which sorts properly by time
    */
    protected static function mintTime(bool $ordered = false): string {
        // Check for native 64-bit integer support
        if (static::$bignum === self::bigChoose) {
            static::$bignum = static::initBignum();
        }
        // ensure a store is available
        if (static::$store === null) {
            static::$store = new UUIDStorageVolatile;
        }
        // Get the current time
        $time = static::normalizeTime(static::now(), 7);
        // Get the node and sequence from storage
        $node = static::$store->getNode() ?? static::makeNode();
        $seq = static::$store->getSequence($time, $node);
        if ($seq === null) {
            $seq = static::seq();
            static::$store->setSequence($seq);
        }
        static::$store->setTimestamp($time);
        // construct a 60-bit timestamp, padded to 64 bits, and combine it with the version bits
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

    /** Generates a Version 7 UUID */
    protected static function mintTime7(): string {
        $time = static::normalizeTime(static::now(), 3);
        // Note that doing base_convert here is safe on 32-bit systems because the floating-point precision threshold is 53 bits, and we're converting a 48-bit timestamp
        $time = base_convert($time, 10, 16);
        $time = pack("H*", str_pad($time, 12, "0", \STR_PAD_LEFT));
        // fill the rest of the UUID with random bytes
        $uuid = $time.static::randomBytes(10);
        // set variant and version
        $uuid[8] = chr(ord($uuid[8]) & self::clearVar | self::varRFC);
        $uuid[6] = chr(ord($uuid[6]) & self::clearVer | self::version7);
        return $uuid;
    }

    /** Generates a Version 4 UUID */
    protected static function mintRand(): string {
        // generate random fields
        $uuid = static::randomBytes(16);
        // set variant
        $uuid[8] = chr(ord($uuid[8]) & self::clearVar | self::varRFC);
        // set version
        $uuid[6] = chr(ord($uuid[6]) & self::clearVer | self::version4);
        return $uuid;
    }

    /** Generates a Version 3 or Version 5 UUID
     * 
     * @param int $ver Which type of hash-based UUID to produce
     * @param ?string $node The name identified by the UUID
     * @param ?string $ns The namespace containing the name
     */
    protected static function mintName(int $ver, ?string $name, ?string $ns): string {
        if ($name === null) {
            throw new \InvalidArgumentException("A name-string is required for Version 3 or 5 UUIDs.");
        }
        // if the namespace UUID isn't binary, make it so
        $ns = static::makeBin($ns);
        if (!$ns) {
            throw new \InvalidArgumentException("A valid UUID namespace is required for Version 3 or 5 UUIDs.");
        }
        switch($ver) {
            case self::MD5:
                $version = self::version3;
                $uuid = md5($ns.$name, true);
                break;
            case self::SHA1:
                $version = self::version5;
                $uuid = substr(sha1($ns.$name, true), 0, 16);
                break;
        }
        // set variant
        $uuid[8] = chr(ord($uuid[8]) & self::clearVar | self::varRFC);
        // set version
        $uuid[6] = chr(ord($uuid[6]) & self::clearVer | $version);
        return ($uuid);
    }

    /** Converts the output of micrtoime() to an integer string with requested precision
     * 
     * @param int $precision The digits of sub-second precision to retain
     */
    protected static function normalizeTime(string $time, int $precision): string {
        $time = explode(" ", $time);
        return $time[1].substr(str_pad($time[0], $precision + 2, "0", \STR_PAD_RIGHT), 2, $precision);
    }

    /** Prepares a 60-bit Gregorian-epoch timestamp from a Unix-epoch timestamp,
     * both with seven-digit sub-second precision
     * 
     * This function is responsible for adding the Gregorian-to-Unix epoch
     * interval to the timestamp, and converting the result to a big-endian binary
     * string. On 32-bit systems this requires arithmetic on numbers which exceed
     * both PHP_MAX_INT and the maximum precision of floating-point numbers, so we
     * need to jump through some hoops in a 32-bit environment, complicating this task.
     */
    protected static function buildTime(string $time): string {
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
                $out = "";
                /* BC Math does not have a native equivalent of base_convert(),
                   so we have to fake it.  Chunking the number to as many
                   nybbles as PHP can handle in an integer speeds things up lots. */
                $base = hexdec(str_repeat("f", (\PHP_INT_SIZE * 2) -1)) + 1;
                do {
                    $mod = bcmod((string) $in, (string) $base);
                    $in = bcdiv((string) $in, (string) $base, 0);
                    $out = base_convert((string) $mod, 10, 16).$out;
                } while($in > 0);
                break;
        }
        // convert to binary, padding to 8 bytes
        return pack("H*", str_pad($out, 16, "0", \STR_PAD_LEFT));
    }

    /** Convert a UUID timestamp (in hexadecimal notation) to a
     * Unix timestamp with microseconds
     * 
     * This operation is the proximate inverse of the buildTime()
     * function, and thus has the same inherent complexities.
     */
    protected static function decodeTimestamp(string $hex): string {
        // Check for native 64-bit integer support
        if (static::$bignum === self::bigChoose) {
            static::$bignum = static::initBignum();
        }
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
                    $time = bcadd((string) $time, bcmul((string) $chunk, (string) $mul));
                    $mul = bcmul((string) $max, (string) $mul);
                } while (sizeof($hex));
                // And finally subtract the magic number to get the correct timestamp
                $time = bcsub((string) $time, self::interval);
                break;
            case self::bigNot:
                $time = static::bigSub(static::bigDec($hex), self::interval);
                break;
        }
        $time = str_pad((string) $time, 8, "0", \STR_PAD_LEFT);
        return substr($time, 0, strlen($time)-7).".".substr($time, strlen($time)-7);
    }

    /** Normalizes a UUID to its binary representation
     * 
     * This is used for comparing two UUIDs or importing a UUID
     * 
     * @param UUID|string $str The UUID to normalize
     * @return string|false
     */
    protected static function makeBin($str) {
        // if the input is already a UUID instance, return its bytes
        if ($str instanceof self) {
            return $str->bytes;
        }
        $str = (string) $str;
        // if the string is exactly 16 bytes long, assume it is a binary UUID
        if (strlen($str) === 16) {
            return $str;
        }
        // reject anything which doesn't look like a UUID (32 hex digits, with or without dashes, enclosed by curly braces, or as a URN)
        if (!preg_match("/^(?:urn:uuid:)?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$|^\{[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\}$|^[0-9a-f]{32}$/i", $str)) {
            return false;
        }
        $str = preg_replace("/^urn:uuid:/is", "", $str); // strip URN scheme and namespace
        $str = preg_replace("/[^a-f0-9]/is", "", $str);  // strip non-hex characters
        return hex2bin($str);
    }

    /** Generates a random node ID
     * 
     * This is simply six random bytes with the least significant bit of the
     * most significant byte set to one.
     */
    protected static function makeNode(): string {
        $node = static::randomBytes(6);
        $node[0] = chr(ord($node[0]) | 1);
        return $node;
    }

    /** Returns the current time with microseconds
     * 
     * This wraps the built-in microtime() function so that it may be easily
     * overridden during testing.
     * 
     * @codeCoverageIgnore
     */
    protected static function now(): string {
        return microtime();
    }

    /** Returns the requested number of random bytes
     * 
     * This wraps the built-in random_bytes() function so that it may be easily
     * overridden during testing.
     * 
     * @codeCoverageIgnore
     */
    protected static function randomBytes(int $count): string {
        return random_bytes($count);
    }

    /** Selects which method to use when performing arithmetic on 60-bit integers
     * 
     * In 64-bit environments the calculation is performed directly; only in
     * 32-bit environments is anything more complex required
     * 
     * @codeCoverageIgnore
     */
    protected static function initBignum(): int {
        if (\PHP_INT_SIZE >= 8) {
            return self::bigNative;
        } else if (function_exists("gmp_add")) {
            return self::bigGMP;
        } else if (function_exists("bcadd")) {
            return self::bigBC;
        }
        return self::bigNot;
    }

    /** Adds two string representations of integers together
     * 
     * This is used to add the interval between Gregorian
     * and Unix epochs to a timestamp. It is not suitable for
     * general purposes; in particular it does not handle
     * negative numbers at all.
     * 
     * This is only used in 32-bit environments in the absence of GMP and BCMath.
     */
    protected static function bigAdd(string $a, string $b): string {
        $d = 1000000000;
        $s = max(strlen($a), strlen($b));
        $a = str_pad($a, $s, "0", \STR_PAD_LEFT);
        $b = str_pad($b, $s, "0", \STR_PAD_LEFT);
        $c = 0;
        $n = "";
        for ($i = $s - 9; $i > -9; $i -= 9) {
            $ss = $i < 0 ? $i + 9 : 9;
            $aa = substr($a, max(0, $i), $ss);
            $bb = substr($b, max(0, $i), $ss);
            $n = (($aa + $bb + $c) % $d).$n;
            $c = intdiv($aa + $bb + $c, $d);
        }
        if ($c) {
            $n = $c.$n; // @codeCoverageIgnore
        }
        return $n;
    }

    /** Performs a subtraction on two string representations of integers
     * 
     * This is used to remove the interval between Gregorian and Unix
     * epochs from a timestamp. It is not suitable for general purposes;
     * in particular it does not handle negative numbers at all, including
     * a negative result from two positive integers. Thus, $b must be
     * less than $a to achieve sensible results.
     * 
     * This is only used in 32-bit environments in the absence of GMP and BCMath.
     */
    protected static function bigSub(string $a, string $b): string {
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
                if ($i > 0) {
                    $nn = 1000000000 + $nn;
                    $c = 1;
                } else {
                    $n = $nn.$n;
                    break;
                }
            } else {
                $c = 0;
            }
            $n = str_pad((string) $nn, 9, "0", \STR_PAD_LEFT).$n;
        }
        return ltrim($n, "0");
    }

    /** Converts a string representation of a decimal integer to hexdecimal
     * 
     * This is only used in 32-bit environments in the absence of GMP and BCMath.
     */
    protected static function bigHex(string $n): string {
        $h = "";
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

    /** Converts a string representation of a hexadecimal integer to decimal
     * 
     * This is only used in 32-bit environments in the absence of GMP and BCMath.
     */
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