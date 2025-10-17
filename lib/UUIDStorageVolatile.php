<?php
namespace JKingWeb\DrUUID;

class UUIDStorageVolatile implements UUIDStorage {
    protected $node = null;
    protected $timestamp = null;
    protected $sequence = null;

    public function getNode(): ?string {
        return $this->node;
    }

    public function getSequence($timestamp, $node): ?string {
        if ($node != $this->node) {
            $this->node = $node;
            return null;
        }
        if ($this->sequence === null) 
            return null;
        if ($timestamp <= $this->timestamp)
            $this->sequence = pack("n", (unpack("nseq", $this->sequence)['seq'] + 1) & self::maxSequence);
        $this->setTimestamp($timestamp);
        return $this->sequence;
    }

    public function setSequence($sequence): void {
        $this->sequence = pack("n", unpack("nseq", $sequence)['seq'] & self::maxSequence);
    }

    public function setTimestamp($timestamp): void {
        $this->timestamp = $timestamp;
    }
}