<?php
use PHPUnit\Framework\TestCase;
use SadranSecurity\Scanners\FileIntegrityScanner;


class FileIntegrityScannerTest extends TestCase {
public function test_can_instantiate() {
$scan = FileIntegrityScanner::instance();
$this->assertInstanceOf(FileIntegrityScanner::class, $scan);
}
}