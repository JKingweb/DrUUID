<?php

use JKingWeb\DrUUID\UUID;
use JKingWeb\DrUUID\UUIDStorage;

require_once("vendor/autoload.php");

// Test data for V1 and V6 UUIDs
define("TEST_TS", new DateTime("2022-02-22T14:22:22-05:00")->format("0.u00 U"));
define("TEST_NODE", hex2bin("9E6BDECED846"));
define("TEST_SEQ", hex2bin("33C8"));
// Test data for V3 and V5 UUIDs
define("TEST_DATA", "www.example.com");
define("TEST_NS", "6ba7b810-9dad-11d1-80b4-00c04fd430c8");
// Test data for V4 UUIDs
define("TEST_RAND4", hex2bin("919108F752D133205BACF847DB4148A8"));
// Test data for V7 UUIDs
define("TEST_RAND7", hex2bin("0CC318C4DC0C0C07398F"));

class Test extends UUID {
    public static function randomBytes(int $bytes): string {
        if ($bytes == 10) {
            return TEST_RAND7;
        } elseif ($bytes == 16) {
            return TEST_RAND4;
        } elseif ($bytes == 6) {
            return TEST_NODE;
        } elseif ($bytes == 2) {
            return TEST_SEQ;
        } else {
            return random_bytes($bytes);
        }
    }

    protected static function now(): string {
        return TEST_TS;
    }
}

class TestStorage implements UUIDStorage {
    public function __construct($ook) {
    }

    public function getNode(): ?string {
        return null;
    }

    public function getSequence($timestamp, $node): ?string {
        return null;
    }

    public function setSequence($sequence): void {
    }

    public function setTimestamp($timestamp): void {
    }
}

$tests = [
    1 => ["C232AB00-9414-11EC-B3C8-9F6BDECED846", [1]],
    3 => ["5df41881-3aed-3515-88a7-2f4a814cf09e", [3, TEST_DATA, TEST_NS]],
    4 => ["919108f7-52d1-4320-9bac-f847db4148a8", [4]],
    5 => ["2ed6657d-e927-568b-95e1-2665a8aea6a2", [5, TEST_DATA, TEST_NS]],
    6 => ["1EC9414C-232A-6B00-B3C8-9F6BDECED846", [6]],
    7 => ["017F22E2-79B0-7CC3-98C4-DC0C0C07398F", [7]],
];

Test::initBignum(TEST::bigNot);
foreach ($tests as $v => [$exp, $params]) {
    Test::registerStorage(TestStorage::class, "ook");
    $exp = strtolower($exp);
    $act = Test::mintStr(...$params);
    if ($act === $exp) {
        echo "V$v: PASS  $act\n";    
    } else {
        echo "V$v: FAIL  $act\n          $exp\n";    
    }
}
