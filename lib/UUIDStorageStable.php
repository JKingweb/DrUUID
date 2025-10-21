<?php
namespace JKingWeb\DrUUID;

class UUIDStorageStable extends UUIDStorageVolatile {
    protected $file = null;
    protected $read = false;
    protected $wrote = true;

    public function __construct($path) {
        if (!file_exists($path)) {
            $dir = dirname($path);
            if (!is_writable($dir))
                throw new UUIDStorageException("Stable storage is not writable.", 1102);
            if (!is_readable($dir))
                throw new UUIDStorageException("Stable storage is not readable.", 1101);
        }
        else if (!is_writable($path))
            throw new UUIDStorageException("Stable storage is not writable.", 1102);
        else if (!is_readable($path))
            throw new UUIDStorageException("Stable storage is not readable.", 1101);
        $this->file = $path;
    }

    protected function readState(): void {
        if (!file_exists($this->file)) // a missing file is not an error
            return;
        $data = @file_get_contents($this->file);
        if ($data === false) throw new UUIDStorageException("Stable storage could not be read.", 1201);
        $this->read = true;
        $this->wrote = false;
        if (!$data) // an empty file is not an error
            return;
        $data = @unserialize($data);
        if (!is_array($data) || sizeof($data) < 3)
            throw new UUIDStorageException("Stable storage data is invalid or corrupted.", 1203);
        list($this->node, $this->sequence, $this->timestamp) = $data;
    }

    public function getNode(): ?string {
        $this->readState();
        return parent::getNode();
    }

    public function setSequence($sequence): void {
        if (!$this->read) {
            $this->readState();
        }
        parent::setSequence($sequence);
        $this->write();
    }

    public function setTimestamp($timestamp): void {
        parent::setTimestamp($timestamp);
        if ($this->wrote)
            return;
        $this->write();
    }

    protected function write($check = 1): void {
        $data = serialize(array($this->node, $this->sequence, $this->timestamp));
        $write = @file_put_contents($this->file, $data);
        if ($check)
            if ($write === false) throw new UUIDStorageException("Stable storage could not be written.", 1202);
        $this->wrote = true;
        $this->read = false;
    }

    public function __destruct() {
        $this->write(0);
    }
}