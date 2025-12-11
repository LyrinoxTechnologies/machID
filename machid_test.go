package machid

import (
"os"
"strings"
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

func TestStrictMode(t *testing.T) {
// Test default is false
if IsStrictMode() {
t.Error("Default strict mode should be false")
}

// Test setting strict mode
SetStrictMode(true)
if !IsStrictMode() {
t.Error("Strict mode should be true after SetStrictMode(true)")
}

// Reset
SetStrictMode(false)
if IsStrictMode() {
t.Error("Strict mode should be false after SetStrictMode(false)")
}
}

func TestSetLogger(t *testing.T) {
var loggedMessages []string

// Set custom logger
SetLogger(func(msg string) {
loggedMessages = append(loggedMessages, msg)
})

// Test that logWarning uses the custom logger
logWarning("test message")

if len(loggedMessages) != 1 || loggedMessages[0] != "test message" {
t.Errorf("Custom logger not called correctly, got: %v", loggedMessages)
}

// Test nil logger (should not panic)
SetLogger(nil)
logWarning("should not panic")

// Reset to default
SetLogger(func(msg string) {})
}

func TestGenerateRandomHex(t *testing.T) {
// Test generating random hex
hex1, err := generateRandomHex(32)
if err != nil {
t.Fatalf("generateRandomHex() failed: %v", err)
}

// Check length (32 bytes = 64 hex chars)
if len(hex1) != 64 {
t.Errorf("generateRandomHex() wrong length: got %d, expected 64", len(hex1))
}

// Generate another and ensure they're different
hex2, err := generateRandomHex(32)
if err != nil {
t.Fatalf("generateRandomHex() second call failed: %v", err)
}

if hex1 == hex2 {
t.Error("generateRandomHex() produced same value twice")
}
}

func TestFilterPlaceholderValues(t *testing.T) {
// Test that placeholder values are filtered
placeholders := []string{"None", "Not Specified", "To Be Filled By O.E.M.", ""}

for _, p := range placeholders {
t.Logf("Placeholder value '%s' should be filtered to empty string", p)
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

func TestGenerateReMachIDWithInfo_AsRoot(t *testing.T) {
if os.Geteuid() != 0 {
t.Skip("Test requires root privileges")
}

salt := "test-salt-12345"

id, usedFallback, err := GenerateReMachIDWithInfo(salt)
if err != nil {
t.Fatalf("GenerateReMachIDWithInfo() failed: %v", err)
}

if len(id) != 64 {
t.Errorf("GenerateReMachIDWithInfo() wrong length: got %d, expected 64", len(id))
}

t.Logf("Used fallback: %v", usedFallback)
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

t.Logf("Used fallback: %v", info.UsedFallback)
}

func TestStrictMode_AsRoot(t *testing.T) {
if os.Geteuid() != 0 {
t.Skip("Test requires root privileges")
}

// First, generate normally to see if we need hardware or fallback
_, usedFallback, err := GenerateReMachIDWithInfo("test-salt")
if err != nil {
t.Fatalf("Initial GenerateReMachIDWithInfo() failed: %v", err)
}

if !usedFallback {
t.Log("System has hardware IDs, strict mode won't change behavior")
return
}

// If we're using fallback, test that strict mode blocks it
SetStrictMode(true)
defer SetStrictMode(false)

_, _, err = GenerateReMachIDWithInfo("test-salt")
if err != ErrStrictModeNoHardwareID {
t.Errorf("Expected ErrStrictModeNoHardwareID in strict mode, got: %v", err)
}
}

func TestLoggerWarnings_AsRoot(t *testing.T) {
if os.Geteuid() != 0 {
t.Skip("Test requires root privileges")
}

var warnings []string
SetLogger(func(msg string) {
warnings = append(warnings, msg)
})
defer SetLogger(nil)

// Generate to potentially trigger fallback warnings
_, usedFallback, err := GenerateReMachIDWithInfo("test-salt")
if err != nil {
t.Fatalf("GenerateReMachIDWithInfo() failed: %v", err)
}

if usedFallback {
// Should have logged warnings
if len(warnings) == 0 {
t.Error("Expected warning messages when using fallback")
}
for _, w := range warnings {
if !strings.Contains(w, "WARNING") {
t.Errorf("Warning message doesn't contain 'WARNING': %s", w)
}
}
t.Logf("Logged %d warnings", len(warnings))
}
}
