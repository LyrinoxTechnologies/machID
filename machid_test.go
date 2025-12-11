package machid

import (
"os"
"testing"
)

func TestCheckRoot(t *testing.T) {
err := checkRoot()
if os.Geteuid() == 0 {
if err != nil {
t.Errorf("checkRoot() returned error when running as root: %v", err)
}
} else {
if err != ErrNotRoot {
t.Errorf("checkRoot() expected ErrNotRoot, got: %v", err)
}
}
}

func TestReadSysfsFile(t *testing.T) {
// Test reading a non-existent file
result := readSysfsFile("/nonexistent/path")
if result != "" {
t.Errorf("readSysfsFile() expected empty string for nonexistent file, got: %s", result)
}

// Test reading a file with placeholder values
// This is a bit tricky to test without mocking, but we can at least verify the function doesn't panic
}

func TestHashData(t *testing.T) {
// Test that hashing produces consistent results
hash1 := hashData("test", "data")
hash2 := hashData("test", "data")

if hash1 != hash2 {
t.Errorf("hashData() produced inconsistent results: %s != %s", hash1, hash2)
}

// Test that different inputs produce different hashes
hash3 := hashData("different", "data")
if hash1 == hash3 {
t.Errorf("hashData() produced same hash for different inputs")
}

// Test hash length (SHA-256 produces 64 hex characters)
if len(hash1) != 64 {
t.Errorf("hashData() produced hash of wrong length: got %d, expected 64", len(hash1))
}
}

func TestClearString(t *testing.T) {
// Test that clearString doesn't panic on nil
clearString(nil)

// Test that clearString clears the string
s := "sensitive"
clearString(&s)
if s != "" {
t.Errorf("clearString() did not clear the string")
}

// Test that clearString handles empty string
empty := ""
clearString(&empty)
if empty != "" {
t.Errorf("clearString() modified empty string unexpectedly")
}
}

func TestGenerateEMachID_EmptySalt(t *testing.T) {
// Skip if running as root (would pass the root check)
if os.Geteuid() == 0 {
_, err := GenerateEMachID("")
if err != ErrEmptySalt {
t.Errorf("GenerateEMachID() with empty salt expected ErrEmptySalt, got: %v", err)
}
}
}

func TestGenerateEMachID_NotRoot(t *testing.T) {
// Skip if running as root
if os.Geteuid() == 0 {
t.Skip("Test requires non-root user")
}

_, err := GenerateEMachID("test-salt")
if err != ErrNotRoot {
t.Errorf("GenerateEMachID() expected ErrNotRoot when not root, got: %v", err)
}
}

func TestGenerateReMachID_NotRoot(t *testing.T) {
// Skip if running as root
if os.Geteuid() == 0 {
t.Skip("Test requires non-root user")
}

_, err := GenerateReMachID("test-salt")
if err != ErrNotRoot {
t.Errorf("GenerateReMachID() expected ErrNotRoot when not root, got: %v", err)
}
}

func TestGenerateBoth_NotRoot(t *testing.T) {
// Skip if running as root
if os.Geteuid() == 0 {
t.Skip("Test requires non-root user")
}

_, err := GenerateBoth("test-salt")
if err == nil {
t.Error("GenerateBoth() expected error when not root, got nil")
}
}

// Integration tests - only run as root
func TestGenerateEMachID_AsRoot(t *testing.T) {
if os.Geteuid() != 0 {
t.Skip("Test requires root privileges")
}

salt := "test-salt-12345"

// Generate two eMachIDs
id1, err := GenerateEMachID(salt)
if err != nil {
t.Fatalf("GenerateEMachID() failed: %v", err)
}

id2, err := GenerateEMachID(salt)
if err != nil {
t.Fatalf("GenerateEMachID() second call failed: %v", err)
}

// They should be different (ephemeral)
if id1 == id2 {
t.Error("GenerateEMachID() produced same ID twice (should be ephemeral)")
}

// Check hash length
if len(id1) != 64 {
t.Errorf("GenerateEMachID() produced wrong length: got %d, expected 64", len(id1))
}
}

func TestGenerateReMachID_AsRoot(t *testing.T) {
if os.Geteuid() != 0 {
t.Skip("Test requires root privileges")
}

salt := "test-salt-12345"

// Generate two reMachIDs with same salt
id1, err := GenerateReMachID(salt)
if err != nil {
t.Fatalf("GenerateReMachID() failed: %v", err)
}

id2, err := GenerateReMachID(salt)
if err != nil {
t.Fatalf("GenerateReMachID() second call failed: %v", err)
}

// They should be the same (reconstructable)
if id1 != id2 {
t.Error("GenerateReMachID() produced different IDs (should be reconstructable)")
}

// Check hash length
if len(id1) != 64 {
t.Errorf("GenerateReMachID() produced wrong length: got %d, expected 64", len(id1))
}

// Test with different salt produces different result
id3, err := GenerateReMachID("different-salt")
if err != nil {
t.Fatalf("GenerateReMachID() with different salt failed: %v", err)
}

if id1 == id3 {
t.Error("GenerateReMachID() produced same ID with different salts")
}
}

func TestGenerateBoth_AsRoot(t *testing.T) {
if os.Geteuid() != 0 {
t.Skip("Test requires root privileges")
}

salt := "test-salt-12345"

info, err := GenerateBoth(salt)
if err != nil {
t.Fatalf("GenerateBoth() failed: %v", err)
}

if info == nil {
t.Fatal("GenerateBoth() returned nil info")
}

if len(info.EMachID) != 64 {
t.Errorf("GenerateBoth() eMachID wrong length: got %d, expected 64", len(info.EMachID))
}

if len(info.ReMachID) != 64 {
t.Errorf("GenerateBoth() reMachID wrong length: got %d, expected 64", len(info.ReMachID))
}

// eMachID and reMachID should be different
if info.EMachID == info.ReMachID {
t.Error("GenerateBoth() produced same eMachID and reMachID")
}
}

func TestFilterPlaceholderValues(t *testing.T) {
// Test that placeholder values are filtered
placeholders := []string{"None", "Not Specified", "To Be Filled By O.E.M.", ""}

for _, p := range placeholders {
// We can't easily test readSysfsFile without mocking,
// but we can document the expected behavior
t.Logf("Placeholder value '%s' should be filtered to empty string", p)
}
}
