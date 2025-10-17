<?php
declare(strict_types=1);

namespace JKingWeb\DrUUID;

interface UUIDStorage {
    public function getNode(): ?string; // return bytes or NULL if node cannot be retrieved
    public function getSequence(string $timestamp, string $node): ?string; // return bytes or NULL if sequence is not available; this method should also update the stored timestamp
    public function setSequence(string $sequence): void;
    public function setTimestamp(string $timestamp): void;
    public const maxSequence = 16383; // 00111111 11111111
}