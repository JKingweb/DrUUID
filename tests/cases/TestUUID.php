<?php
declare(strict_types=1);

namespace JKingWeb\DrUUID\TestCase;

use JKingWeb\DrUUID\UUID;
use JKingWeb\DrUUID\UUIDStorageVolatile;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

#[CoversClass(UUID::class)]
#[CoversClass(UUIDStorageVolatile::class)]
class TestUUID extends TestCase {
    protected function makeClass(string $name, array $rand, \DateTimeInterface $time, ?string $bignum = "bigNot"): string {
        $time = $time->format("0.u00 U");
        $rand = var_export($rand, true);
        return <<<PHP_CODE
class $name extends \\JKingWeb\\DrUUID\\UUID {
    protected static \$bignum = self::$bignum;
    protected static \$store = null;

    protected static function randomBytes(int \$count): string {
        return hex2bin({$rand}[\$count] ?? bin2hex(random_bytes(\$count)));
    }
    
    protected static function now(): string {
        return "$time";
    }
};
PHP_CODE;
    }

    #[DataProvider("provideStandardTests")]
    public function testStandardTests(string $exp, array $in): void {
        $exp = strtolower($exp); // some test data in RFC 9562 are uppercase, for whatever reason
        $date = new \DateTime("2022-02-22T14:22:22-05:00");
        $rand = [
            2  => "33C8", // clock sequence for V1 and V6
            6  => "9E6BDECED846", // random node for V1 and V6
            10 => "0CC318C4DC0C0C07398F", // random bytes for V7
            16 => "919108F752D133205BACF847DB4148A8", // random bytes for V4
        ];
        $class = @array_pop(explode("\\", __CLASS__))."_".__FUNCTION__;
        if (!class_exists($class)) {
            eval($this->makeClass($class, $rand, $date));
        }
        $class::registerStorage(new UUIDStorageVolatile);
        $act = $class::mintStr(...$in);
        $this->assertSame($exp, $act);
        $class::registerStorage(new UUIDStorageVolatile);
        $act = $class::mint(...$in);
        $this->assertSame($exp, (string) $act);
        // check the properties of the UUID object while we're at it
        $ver = $in[0];
        $node = strtolower($rand[6]);
        $node[1] = dechex(hexdec($node[1]) | 1);
        $time = $date->format("U.");
        $time1 = $time.$date->format("u0");
        $time7 = $time.substr($date->format("u"), 0, 3);
        $this->assertSame(hex2bin(str_replace("-", "", $exp)), $act->bytes);
        $this->assertSame(str_replace("-", "", $exp), $act->hex);
        $this->assertSame($exp, $act->string);
        $this->assertSame("urn:uuid:".$exp, $act->urn);
        $this->assertSame($ver, $act->version);
        $this->assertSame(1, $act->variant);
        $this->assertSame(in_array($ver, [1, 6]) ? $node : null, $act->node);
        $this->assertSame(in_array($ver, [1, 6, 7]) ? ($ver === 7 ? $time7 : $time1) : null, $act->time);
        $this->assertNull($act->ook);
    }

    public static function provideStandardTests(): iterable {
        return [
            'Version 1' => ["C232AB00-9414-11EC-B3C8-9F6BDECED846", [1]],
            'Version 3' => ["5df41881-3aed-3515-88a7-2f4a814cf09e", [3, "www.example.com", "6ba7b810-9dad-11d1-80b4-00c04fd430c8"]],
            'Version 4' => ["919108f7-52d1-4320-9bac-f847db4148a8", [4]],
            'Version 5' => ["2ed6657d-e927-568b-95e1-2665a8aea6a2", [5, "www.example.com", "6ba7b810-9dad-11d1-80b4-00c04fd430c8"]],
            'Version 6' => ["1EC9414C-232A-6B00-B3C8-9F6BDECED846", [6]],
            'Version 7' => ["017F22E2-79B0-7CC3-98C4-DC0C0C07398F", [7]],
        ];
    }

    #[DataProvider("provideUnsupportedVersions")]
    public function testRejectUnsupportedVersions(int $ver): void {
        $this->expectException("\\InvalidArgumentException");
        UUID::mint($ver);
    }

    #[DataProvider("provideUnsupportedVersions")]
    public function testRejectUnsupportedVersionsAsString(int $ver): void {
        $this->expectException(\InvalidArgumentException::class);
        UUID::mintStr($ver);
    }

    public static function provideUnsupportedVersions(): iterable {
        return array_map(fn($v) => (array) $v, [0, 2, 8, 9, 10, 11, 12, 13, 14, 15]);
    }

    #[DataProvider("provideValidImports")]
    public function testImportVariousVersions(string $in, int $variant, ?int $version, ?string $node, ?string $time): void {
        $act = UUID::import($in);
        $this->assertSame($variant, $act->variant);
        $this->assertSame($version, $act->version);
        $this->assertSame($node, $act->node);
        $this->assertSame($time, $act->time);
    }

    public static function provideValidImports(): iterable {
        return [
            ["00000000-0000-0000-0000-000000000000",          0, null, null,           null],
            ["ffffffff-ffff-ffff-7fff-ffffffffffff",          0, null, null,           null],
            ["00000000-0000-0000-8000-000000000000",          1, 0,    null,           null],
            ["C232AB00-9414-11EC-B3C8-9F6BDECED846",          1, 1,    "9f6bdeced846", "1645557742.0000000"],
            ["00000000-0000-2000-8000-000000000000",          1, 2,    null,           null],
            ["ffffffff-ffff-2fff-bfff-ffffffffffff",          1, 2,    null,           null],
            ["5df41881-3aed-3515-88a7-2f4a814cf09e",          1, 3,    null,           null],
            ["919108f7-52d1-4320-9bac-f847db4148a8",          1, 4,    null,           null],
            ["2ed6657d-e927-568b-95e1-2665a8aea6a2",          1, 5,    null,           null],
            ["1EC9414C-232A-6B00-B3C8-9F6BDECED846",          1, 6,    "9f6bdeced846", "1645557742.0000000"],
            ["017F22E2-79B0-7CC3-98C4-DC0C0C07398F",          1, 7,    null,           "1645557742.000"],
            ["00000000-0000-8000-8000-000000000000",          1, 8,    null,           null],
            ["ffffffff-0000-8fff-bfff-ffffffffffff",          1, 8,    null,           null],
            ["00000000-0000-9000-8000-000000000000",          1, 9,    null,           null],
            ["ffffffff-0000-9fff-bfff-ffffffffffff",          1, 9,    null,           null],
            ["00000000-0000-a000-8000-000000000000",          1, 10,   null,           null],
            ["ffffffff-0000-afff-bfff-ffffffffffff",          1, 10,   null,           null],
            ["00000000-0000-b000-8000-000000000000",          1, 11,   null,           null],
            ["ffffffff-0000-bfff-bfff-ffffffffffff",          1, 11,   null,           null],
            ["00000000-0000-c000-8000-000000000000",          1, 12,   null,           null],
            ["ffffffff-0000-cfff-bfff-ffffffffffff",          1, 12,   null,           null],
            ["00000000-0000-d000-8000-000000000000",          1, 13,   null,           null],
            ["ffffffff-0000-dfff-bfff-ffffffffffff",          1, 13,   null,           null],
            ["00000000-0000-e000-8000-000000000000",          1, 14,   null,           null],
            ["ffffffff-0000-efff-bfff-ffffffffffff",          1, 14,   null,           null],
            ["00000000-0000-f000-8000-000000000000",          1, 15,   null,           null],
            ["ffffffff-0000-ffff-bfff-ffffffffffff",          1, 15,   null,           null],
            ["00000000-0000-0000-c000-000000000000",          2, null, null,           null],
            ["ffffffff-ffff-ffff-dfff-ffffffffffff",          2, null, null,           null],
            ["00000000-0000-0000-e000-000000000000",          3, null, null,           null],
            ["ffffffff-ffff-ffff-ffff-ffffffffffff",          3, null, null,           null],
            ["{C232AB00-9414-11EC-B3C8-9F6BDECED846}",        1, 1,    "9f6bdeced846", "1645557742.0000000"],
            ["C232AB00941411ECB3C89F6BDECED846",              1, 1,    "9f6bdeced846", "1645557742.0000000"],
            [hex2bin("C232AB00941411ECB3C89F6BDECED846"),     1, 1,    "9f6bdeced846", "1645557742.0000000"],
            ["urn:uuid:C232AB00-9414-11EC-B3C8-9F6BDECED846", 1, 1,    "9f6bdeced846", "1645557742.0000000"],
            ["URN:UUID:C232AB00-9414-11EC-B3C8-9F6BDECED846", 1, 1,    "9f6bdeced846", "1645557742.0000000"],
        ];
    }

    #[TestWith([""])]
    #[TestWith(["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"])]
    #[TestWith(["xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"])]
    #[TestWith(["ffffffff_ffff_ffff_ffff_ffffffffffff"])]
    #[TestWith(["ffffffff-ffffffffffffffffffffffff"])]
    #[TestWith(["{ffffffffffffffffffffffffffffffff"])]
    #[TestWith([" ffffffffffffffffffffffffffffffff"])]
    #[TestWith(["urn:uuid:ffffffffffffffffffffffffffffffff"])]
    public function testImportFailure(string $in): void {
        $this->assertFalse(UUID::import($in));
    }

    #[TestWith(["bigNative"])]
    #[TestWith(["bigGMP"])]
    #[TestWith(["bigBC"])]
    #[TestWith(["bigChoose"])]
    public function testLargeIntegerHandling(string $method): void {
        switch ($method) {
            case "bigNative":
                if (\PHP_INT_SIZE < 8) {
                    $this->markTestSkipped("This test is only accurate in 64-bit environments");
                }
                break;
            case "bigGMP":
                if (!extension_loaded("gmp")) {
                    $this->markTestSkipped("This test requires the GMP extension to be loaded");
                }
                break;
            case "bigBC":
                if (!extension_loaded("bcmath")) {
                    $this->markTestSkipped("This test requires the BCMath extension to be loaded");
                }
                break;
        }
        $t = new \DateTime;
        $exp = $t->format("U.u0");
        $class = implode("_", [@array_pop(explode("\\", __CLASS__)), __FUNCTION__, $method]);
        eval($this->makeClass($class, [], $t, $method));
        $uuid = $class::mint(1);
        $this->assertSame($exp, $uuid->time);
        $uuid = $class::mint(6);
        $this->assertSame($exp, $uuid->time);
    }

    #[TestWith(["mint",    [3]])]
    #[TestWith(["mint",    [3, null, null]])]
    #[TestWith(["mint",    [3, null, UUID::nsURL]])]
    #[TestWith(["mint",    [3, "example", "bogus"]])]
    #[TestWith(["mintStr", [3]])]
    #[TestWith(["mintStr", [3, null, null]])]
    #[TestWith(["mintStr", [3, null, UUID::nsURL]])]
    #[TestWith(["mintStr", [3, "example", "bogus"]])]
    #[TestWith(["mint",    [5]])]
    #[TestWith(["mint",    [5, null, null]])]
    #[TestWith(["mint",    [5, null, UUID::nsURL]])]
    #[TestWith(["mint",    [5, "example", "bogus"]])]
    #[TestWith(["mintStr", [5]])]
    #[TestWith(["mintStr", [5, null, null]])]
    #[TestWith(["mintStr", [5, null, UUID::nsURL]])]
    #[TestWith(["mintStr", [5, "example", "bogus"]])]
    public function testMintNameIncorrectly(string $method, array $in): void {
        $this->expectException(\InvalidArgumentException::class);
        UUID::$method(...$in);
    }
}