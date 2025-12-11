// Package machid provides machine identification generation for Linux systems.
// It generates two types of machine IDs:
// - eMachID (Ephemeral Machine Identifier): A unique, one-time ID based on current time and salt
// - reMachID (Reconstructable Machine Identifier): A reproducible ID based on hardware identifiers
package machid

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
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
)

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

// getHardwareIdentifiers attempts to retrieve hardware identifiers from sysfs,
// falling back to dmidecode if necessary.
func getHardwareIdentifiers() (serial, uuid string, err error) {
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
		return serial, uuid, nil
	}

	// Try dmidecode as fallback
	var dmidecodeErr error

	if serial == "" {
		serial, dmidecodeErr = getDmidecodeValue("system-serial-number")
		if dmidecodeErr != nil {
			return "", "", dmidecodeErr
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
		if dmidecodeErr != nil && serial == "" {
			// Only return dmidecode error if we have no data at all
			return "", "", dmidecodeErr
		}
	}

	// Check if we got at least one identifier
	if serial == "" && uuid == "" {
		return "", "", ErrNoHardwareID
	}

	return serial, uuid, nil
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
//
// Parameters:
//   - salt: An optional string to add to the hash for additional uniqueness per application
//
// Returns:
//   - The reMachID as a hex-encoded SHA-256 hash
//   - An error if root privileges are missing or hardware IDs cannot be retrieved
//
// Security: All hardware identifiers are cleared from memory after hashing.
func GenerateReMachID(salt string) (string, error) {
	if err := checkRoot(); err != nil {
		return "", err
	}

	serial, uuid, err := getHardwareIdentifiers()
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

// MachIDInfo contains both types of machine identifiers.
type MachIDInfo struct {
	EMachID  string // Ephemeral Machine Identifier
	ReMachID string // Reconstructable Machine Identifier
}

// GenerateBoth generates both eMachID and reMachID in a single call.
//
// Parameters:
//   - salt: A non-empty string used for both identifiers
//
// Returns:
//   - A MachIDInfo struct containing both identifiers
//   - An error if generation fails for either identifier
func GenerateBoth(salt string) (*MachIDInfo, error) {
	emachid, err := GenerateEMachID(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate eMachID: %w", err)
	}

	remachid, err := GenerateReMachID(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate reMachID: %w", err)
	}

	return &MachIDInfo{
		EMachID:  emachid,
		ReMachID: remachid,
	}, nil
}
