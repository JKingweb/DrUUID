<?php
declare(strict_types=1);

namespace JKingWeb\DrUUID\TestCase;

use JKingWeb\DrUUID\UUID;
use JKingWeb\DrUUID\UUIDStorage;
use JKingWeb\DrUUID\UUIDStorageVolatile;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(UUID::class)]
class TestUUID extends TestCase {
    protected function makeClass(string $name, array $rand, \DateTimeInterface $time, ?string $bignum = "bigNot"): string {
        $time = $time->format("0.u00 U");
        $rand = var_export($rand, true);
        return <<<PHP_CODE
class $name extends \\JKingWeb\\DrUUID\\UUID {
    protected static \$bignum = self::$bignum;

    protected static function randomBytes(int \$count): string {
        return hex2bin({$rand}[\$count]);
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
        $this->expectException("\\InvalidArgumentException");
        UUID::mintStr($ver);
    }

    public static function provideUnsupportedVersions(): iterable {
        return array_map(fn($v) => (array) $v, [0, 2, 8, 9, 10, 11, 12, 13, 14, 15]);
    }
}