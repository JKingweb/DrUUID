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
    public function tearDown(): void {
        \Phake::resetStaticInfo();
    }

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
        $time = new \DateTime("2022-02-22T14:22:22-05:00");
        $rand = [
            2  => "33C8", // clock sequence for V1 and V6
            6  => "9E6BDECED846", // random node for V1 and V6
            10 => "0CC318C4DC0C0C07398F", // random bytes for V7
            16 => "919108F752D133205BACF847DB4148A8", // random bytes for V4
        ];
        $class = @array_pop(explode("\\", __CLASS__))."_".__FUNCTION__;
        if (!class_exists($class)) {
            eval($this->makeClass($class, $rand, $time));
        }
        $class::registerStorage(new UUIDStorageVolatile);
        $act = $class::mintStr(...$in);
        $this->assertSame($exp, $act);
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
}