// Package machid provides machine identification generation for Linux systems.
// It generates two types of machine IDs:
// - eMachID (Ephemeral Machine Identifier): A unique, one-time ID based on current time and salt
// - reMachID (Reconstructable Machine Identifier): A reproducible ID based on hardware identifiers
package machid

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Error definitions
var (
	// ErrNotRoot is returned when the library is called without root privileges
	ErrNotRoot = errors.New("machid: root privileges required (run with sudo)")

	// ErrEmptySalt is returned when an empty salt is provided for eMachID generation
	ErrEmptySalt = errors.New("machid: salt cannot be empty")

	// ErrNoHardwareID is returned when no hardware identifiers can be found
	ErrNoHardwareID = errors.New("machid: unable to retrieve hardware identifiers from sysfs or dmidecode")

	// ErrDmidecodeNotFound is returned when dmidecode is needed but not installed
	ErrDmidecodeNotFound = errors.New("machid: dmidecode not found, please install it (e.g., apt install dmidecode)")

	// ErrStrictModeNoHardwareID is returned in strict mode when hardware IDs are unavailable
	ErrStrictModeNoHardwareID = errors.New("machid: strict mode enabled - hardware identifiers unavailable and filesystem fallback is disabled")

	// ErrFallbackFileCreation is returned when fallback files cannot be created
	ErrFallbackFileCreation = errors.New("machid: failed to create filesystem fallback files")
)

// Configuration
var (
	// strictMode when true, disables filesystem fallback for machine IDs
	strictMode   bool
	strictModeMu sync.RWMutex

	// Logger function for warnings (defaults to fmt.Println to stdout)
	// Can be overridden by SetLogger
	loggerFunc   func(msg string)
	loggerFuncMu sync.RWMutex

	// Fallback file paths (hidden in /etc)
	fallbackDir        = "/etc/.machid"
	fallbackSerialFile = ".mserial"
	fallbackUUIDFile   = ".muuid"

	// Fallback data length (64 random bytes = 128 hex chars before hashing)
	fallbackDataLength = 64
)

func init() {
	// Default logger writes to stdout
	loggerFunc = func(msg string) {
		fmt.Println(msg)
	}
}

// sysfs paths for hardware identifiers
var sysfsPaths = struct {
	productSerial string
	productUUID   string
	chassisSerial string
	boardSerial   string
}{
	productSerial: "/sys/class/dmi/id/product_serial",
	productUUID:   "/sys/class/dmi/id/product_uuid",
	chassisSerial: "/sys/class/dmi/id/chassis_serial",
	boardSerial:   "/sys/class/dmi/id/board_serial",
}

// SetStrictMode enables or disables strict mode.
// When strict mode is enabled, the library will NOT fall back to filesystem-based
// machine IDs when hardware identifiers are unavailable. Instead, it will return
// an error.
//
// Parameters:
//   - enabled: true to enable strict mode, false to allow filesystem fallback
func SetStrictMode(enabled bool) {
	strictModeMu.Lock()
	defer strictModeMu.Unlock()
	strictMode = enabled
}

// IsStrictMode returns whether strict mode is currently enabled.
func IsStrictMode() bool {
	strictModeMu.RLock()
	defer strictModeMu.RUnlock()
	return strictMode
}

// SetLogger sets a custom logger function for warning messages.
// This is useful for integrating with existing logging frameworks.
//
// Parameters:
//   - logger: A function that accepts a string message. Pass nil to disable logging.
func SetLogger(logger func(msg string)) {
	loggerFuncMu.Lock()
	defer loggerFuncMu.Unlock()
	if logger == nil {
		loggerFunc = func(msg string) {} // No-op
	} else {
		loggerFunc = logger
	}
}

// logWarning logs a warning message using the configured logger.
func logWarning(msg string) {
	loggerFuncMu.RLock()
	defer loggerFuncMu.RUnlock()
	loggerFunc(msg)
}

// checkRoot verifies that the current process is running with root privileges.
func checkRoot() error {
	if os.Geteuid() != 0 {
		return ErrNotRoot
	}
	return nil
}

// readSysfsFile attempts to read a sysfs file and returns its trimmed content.
// Returns empty string if the file cannot be read or contains only whitespace.
func readSysfsFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	content := strings.TrimSpace(string(data))
	// Filter out placeholder values that indicate no real data
	if content == "" || content == "None" || content == "Not Specified" || content == "To Be Filled By O.E.M." {
		return ""
	}
	return content
}

// getDmidecodeValue attempts to get a value from dmidecode.
// Returns empty string if dmidecode fails or the value is not found.
func getDmidecodeValue(keyword string) (string, error) {
	// Check if dmidecode exists
	_, err := exec.LookPath("dmidecode")
	if err != nil {
		return "", ErrDmidecodeNotFound
	}

	cmd := exec.Command("dmidecode", "-s", keyword)
	output, err := cmd.Output()
	if err != nil {
		return "", nil // Return empty string on failure, not an error
	}

	content := strings.TrimSpace(string(output))
	// Filter out placeholder values
	if content == "" || content == "None" || content == "Not Specified" || content == "To Be Filled By O.E.M." {
		return "", nil
	}
	return content, nil
}

// generateRandomHex generates a cryptographically secure random hex string.
func generateRandomHex(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// ensureFallbackFiles creates the fallback directory and files if they don't exist.
// Returns the serial and uuid values from the files.
func ensureFallbackFiles() (serial, uuid string, err error) {
	// Create hidden directory with restrictive permissions
	if err := os.MkdirAll(fallbackDir, 0700); err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrFallbackFileCreation, err)
	}

	serialPath := filepath.Join(fallbackDir, fallbackSerialFile)
	uuidPath := filepath.Join(fallbackDir, fallbackUUIDFile)

	// Check if serial file exists, create if not
	serial, err = readOrCreateFallbackFile(serialPath)
	if err != nil {
		return "", "", err
	}

	// Check if UUID file exists, create if not
	uuid, err = readOrCreateFallbackFile(uuidPath)
	if err != nil {
		return "", "", err
	}

	return serial, uuid, nil
}

// readOrCreateFallbackFile reads an existing fallback file or creates a new one with random data.
func readOrCreateFallbackFile(path string) (string, error) {
	// Try to read existing file
	data, err := os.ReadFile(path)
	if err == nil {
		content := strings.TrimSpace(string(data))
		if content != "" {
			return content, nil
		}
	}

	// File doesn't exist or is empty, create new one
	randomData, err := generateRandomHex(fallbackDataLength)
	if err != nil {
		return "", fmt.Errorf("%w: failed to generate random data: %v", ErrFallbackFileCreation, err)
	}

	// Write with restrictive permissions (owner read/write only)
	if err := os.WriteFile(path, []byte(randomData), 0600); err != nil {
		return "", fmt.Errorf("%w: %v", ErrFallbackFileCreation, err)
	}

	return randomData, nil
}

// getHardwareIdentifiers attempts to retrieve hardware identifiers from sysfs,
// falling back to dmidecode if necessary.
// Returns (serial, uuid, usedFallback, error)
func getHardwareIdentifiers() (serial, uuid string, usedFallback bool, err error) {
	// Try sysfs first for product serial
	serial = readSysfsFile(sysfsPaths.productSerial)
	if serial == "" {
		serial = readSysfsFile(sysfsPaths.chassisSerial)
	}
	if serial == "" {
		serial = readSysfsFile(sysfsPaths.boardSerial)
	}

	// Try sysfs for product UUID
	uuid = readSysfsFile(sysfsPaths.productUUID)

	// If we have both, return them
	if serial != "" && uuid != "" {
		return serial, uuid, false, nil
	}

	// Try dmidecode as fallback
	var dmidecodeErr error

	if serial == "" {
		serial, dmidecodeErr = getDmidecodeValue("system-serial-number")
		if dmidecodeErr != nil && dmidecodeErr != ErrDmidecodeNotFound {
			return "", "", false, dmidecodeErr
		}
		if serial == "" {
			serial, _ = getDmidecodeValue("chassis-serial-number")
		}
		if serial == "" {
			serial, _ = getDmidecodeValue("baseboard-serial-number")
		}
	}

	if uuid == "" {
		uuid, dmidecodeErr = getDmidecodeValue("system-uuid")
		// Ignore dmidecode errors here, we'll handle missing data below
	}

	// Check if we got at least one identifier from hardware
	if serial != "" || uuid != "" {
		return serial, uuid, false, nil
	}

	// No hardware identifiers available - check strict mode
	strictModeMu.RLock()
	isStrict := strictMode
	strictModeMu.RUnlock()

	if isStrict {
		return "", "", false, ErrStrictModeNoHardwareID
	}

	// Log warning about using filesystem fallback
	logWarning("WARNING: machid - BIOS is not providing the system variables (serial/UUID) needed to generate hardware-based machine IDs.")
	logWarning("WARNING: machid - Falling back to filesystem-based machine IDs stored in " + fallbackDir)
	logWarning("WARNING: machid - These IDs will persist across reboots but are NOT tied to hardware.")

	// Use filesystem fallback
	serial, uuid, err = ensureFallbackFiles()
	if err != nil {
		return "", "", false, err
	}

	return serial, uuid, true, nil
}

// hashData creates a SHA-256 hash of the input data and returns it as a hex string.
// The input data is cleared from memory after hashing.
func hashData(data ...string) string {
	hasher := sha256.New()
	for _, d := range data {
		hasher.Write([]byte(d))
	}
	hash := hasher.Sum(nil)
	result := hex.EncodeToString(hash)

	// Clear sensitive data from memory (best effort)
	for i := range data {
		clearString(&data[i])
	}

	return result
}

// clearString attempts to clear a string from memory by zeroing its underlying bytes.
// Note: This is a best-effort approach due to Go's string immutability.
func clearString(s *string) {
	if s == nil || *s == "" {
		return
	}
	// Overwrite with empty string
	*s = ""
}

// GenerateEMachID generates an Ephemeral Machine Identifier.
// This ID is unique and can only be generated once (based on current Unix nanosecond time and salt).
//
// Parameters:
//   - salt: A non-empty string used to add entropy to the hash
//
// Returns:
//   - The eMachID as a hex-encoded SHA-256 hash
//   - An error if root privileges are missing or salt is empty
//
// Security: The salt and time values are cleared from memory after hashing.
func GenerateEMachID(salt string) (string, error) {
	if err := checkRoot(); err != nil {
		return "", err
	}

	if salt == "" {
		return "", ErrEmptySalt
	}

	// Get current time in nanoseconds for maximum uniqueness
	timestamp := fmt.Sprintf("%d", time.Now().UnixNano())

	// Create the hash
	emachid := hashData(timestamp, salt)

	// Clear the salt copy (the original is the caller's responsibility)
	clearString(&timestamp)

	return emachid, nil
}

// GenerateReMachID generates a Reconstructable Machine Identifier.
// This ID is reproducible - the same hardware will always generate the same ID.
//
// The ID is generated from hardware identifiers found in:
//   - /sys/class/dmi/id/product_serial (or chassis_serial, board_serial)
//   - /sys/class/dmi/id/product_uuid
//
// If sysfs is not available, it falls back to dmidecode.
// If no hardware identifiers are available and strict mode is disabled (default),
// it falls back to filesystem-based identifiers stored in /etc/.machid/
//
// Parameters:
//   - salt: An optional string to add to the hash for additional uniqueness per application
//
// Returns:
//   - The reMachID as a hex-encoded SHA-256 hash
//   - An error if root privileges are missing or hardware IDs cannot be retrieved
//
// Security: All hardware identifiers are cleared from memory after hashing.
//
// Note: If filesystem fallback is used, a warning will be logged to stdout.
// Use SetStrictMode(true) to disable the filesystem fallback.
func GenerateReMachID(salt string) (string, error) {
	if err := checkRoot(); err != nil {
		return "", err
	}

	serial, uuid, _, err := getHardwareIdentifiers()
	if err != nil {
		return "", err
	}

	// Create the hash with serial, uuid, and optional salt
	var remachid string
	if salt != "" {
		remachid = hashData(serial, uuid, salt)
	} else {
		remachid = hashData(serial, uuid)
	}

	// Clear sensitive data
	clearString(&serial)
	clearString(&uuid)

	return remachid, nil
}

// GenerateReMachIDWithInfo generates a Reconstructable Machine Identifier and returns
// additional information about how it was generated.
//
// This is the same as GenerateReMachID but also returns whether the filesystem
// fallback was used.
//
// Parameters:
//   - salt: An optional string to add to the hash for additional uniqueness per application
//
// Returns:
//   - The reMachID as a hex-encoded SHA-256 hash
//   - usedFallback: true if filesystem fallback was used instead of hardware IDs
//   - An error if generation fails
func GenerateReMachIDWithInfo(salt string) (remachid string, usedFallback bool, err error) {
	if err := checkRoot(); err != nil {
		return "", false, err
	}

	serial, uuid, usedFallback, err := getHardwareIdentifiers()
	if err != nil {
		return "", false, err
	}

	// Create the hash with serial, uuid, and optional salt
	if salt != "" {
		remachid = hashData(serial, uuid, salt)
	} else {
		remachid = hashData(serial, uuid)
	}

	// Clear sensitive data
	clearString(&serial)
	clearString(&uuid)

	return remachid, usedFallback, nil
}

// MachIDInfo contains both types of machine identifiers.
type MachIDInfo struct {
	EMachID      string // Ephemeral Machine Identifier
	ReMachID     string // Reconstructable Machine Identifier
	UsedFallback bool   // True if filesystem fallback was used for reMachID
}

// GenerateBoth generates both eMachID and reMachID in a single call.
//
// Parameters:
//   - salt: A non-empty string used for both identifiers
//
// Returns:
//   - A MachIDInfo struct containing both identifiers and fallback status
//   - An error if generation fails for either identifier
func GenerateBoth(salt string) (*MachIDInfo, error) {
	emachid, err := GenerateEMachID(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate eMachID: %w", err)
	}

	remachid, usedFallback, err := GenerateReMachIDWithInfo(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate reMachID: %w", err)
	}

	return &MachIDInfo{
		EMachID:      emachid,
		ReMachID:     remachid,
		UsedFallback: usedFallback,
	}, nil
}

// ClearFallbackFiles removes the filesystem fallback files if they exist.
// This can be used to regenerate new filesystem-based IDs.
//
// Returns an error if the files exist but cannot be removed.
func ClearFallbackFiles() error {
	if err := checkRoot(); err != nil {
		return err
	}

	serialPath := filepath.Join(fallbackDir, fallbackSerialFile)
	uuidPath := filepath.Join(fallbackDir, fallbackUUIDFile)

	// Remove serial file
	if err := os.Remove(serialPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove fallback serial file: %w", err)
	}

	// Remove UUID file
	if err := os.Remove(uuidPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove fallback UUID file: %w", err)
	}

	// Try to remove the directory (will fail if not empty, which is fine)
	os.Remove(fallbackDir)

	return nil
}

// HasFallbackFiles returns true if the filesystem fallback files exist.
func HasFallbackFiles() bool {
	serialPath := filepath.Join(fallbackDir, fallbackSerialFile)
	uuidPath := filepath.Join(fallbackDir, fallbackUUIDFile)

	_, serialErr := os.Stat(serialPath)
	_, uuidErr := os.Stat(uuidPath)

	return serialErr == nil && uuidErr == nil
}
