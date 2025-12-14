// Package machid provides machine identification generation for Linux systems.
// It generates two types of machine IDs:
// - eMachID (Ephemeral Machine Identifier): A unique, one-time ID based on current time and salt
// - reMachID (Reconstructable Machine Identifier): A reproducible ID based on hardware identifiers
package machid

import (
"crypto/rand"
"crypto/sha256"
"encoding/hex"
"encoding/json"
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
// Unlike GenerateReMachID, this function does NOT require root privileges since
// it only uses the current timestamp and salt, not hardware identifiers.
//
// Parameters:
//   - salt: A non-empty string used to add entropy to the hash
//
// Returns:
//   - The eMachID as a hex-encoded SHA-256 hash
//   - An error if salt is empty
//
// Security: The salt and time values are cleared from memory after hashing.
func GenerateEMachID(salt string) (string, error) {
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

// ================================================================================
// Caching API
// ================================================================================
//
// The caching system allows applications to cache machine IDs to avoid requiring
// sudo on every run. The first run with sudo generates and caches the IDs, and
// subsequent runs can use the cached values without elevated privileges.

// CachedMachineIDs holds cached machine identifiers
type CachedMachineIDs struct {
ReMachID    string `json:"remach_id"`
EMachID     string `json:"emach_id,omitempty"`
Salt        string `json:"salt,omitempty"`
ActionCount int    `json:"action_count"`
CreatedAt   int64  `json:"created_at,omitempty"`
}

// Default cache directory (user-specific)
var (
cacheSubDir  = ".config/machid"
cacheFile    = "cache.json"
)

// getCacheDir returns the appropriate cache directory based on sudo status
func getCacheDir() string {
var home string

// Check if running with sudo - use the real user's home
if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
home = filepath.Join("/home", sudoUser)
if _, err := os.Stat(home); err != nil {
// Fallback to /tmp
return filepath.Join("/tmp", cacheSubDir)
}
} else {
var err error
home, err = os.UserHomeDir()
if err != nil {
return filepath.Join("/tmp", cacheSubDir)
}
}

return filepath.Join(home, cacheSubDir)
}

// getCachePath returns the full path to the cache file
func getCachePath() string {
return filepath.Join(getCacheDir(), cacheFile)
}

// LoadCachedIDs loads cached machine IDs from disk.
// Returns nil if no cache exists or cache is invalid.
func LoadCachedIDs() (*CachedMachineIDs, error) {
data, err := os.ReadFile(getCachePath())
if err != nil {
return nil, err
}

var cache CachedMachineIDs
if err := json.Unmarshal(data, &cache); err != nil {
return nil, err
}

return &cache, nil
}

// SaveCachedIDs saves machine IDs to the cache file.
// When running with sudo, it fixes ownership so the real user can read the file.
func SaveCachedIDs(cache *CachedMachineIDs) error {
cacheDir := getCacheDir()
if err := os.MkdirAll(cacheDir, 0755); err != nil {
return err
}

data, err := json.MarshalIndent(cache, "", "  ")
if err != nil {
return err
}

cachePath := getCachePath()
if err := os.WriteFile(cachePath, data, 0644); err != nil {
return err
}

// If running with sudo, fix ownership so the real user can read it
if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
if uidStr := os.Getenv("SUDO_UID"); uidStr != "" {
if gidStr := os.Getenv("SUDO_GID"); gidStr != "" {
var uid, gid int
fmt.Sscanf(uidStr, "%d", &uid)
fmt.Sscanf(gidStr, "%d", &gid)
os.Chown(cacheDir, uid, gid)
os.Chown(cachePath, uid, gid)
}
}
}

return nil
}

// ClearCache removes the cached machine IDs.
func ClearCache() error {
cachePath := getCachePath()
if err := os.Remove(cachePath); err != nil && !os.IsNotExist(err) {
return err
}
return nil
}

// GetOrGenerateReMachID attempts to load the cached reMachID, or generates a new one.
// If generation is needed, sudo is required. The generated ID is cached for future use.
//
// Parameters:
//   - salt: Salt for the machine ID (must match previous runs for consistent IDs)
//
// Returns:
//   - The reMachID
//   - Whether the ID was loaded from cache (true) or freshly generated (false)
//   - An error if generation fails (including if sudo is required but not available)
func GetOrGenerateReMachID(salt string) (remachid string, fromCache bool, err error) {
// Try loading from cache first
cache, err := LoadCachedIDs()
if err == nil && cache.ReMachID != "" {
// Verify salt matches if provided in cache
if cache.Salt == "" || cache.Salt == salt {
return cache.ReMachID, true, nil
}
// Salt mismatch - need to regenerate
logWarning("WARNING: machid - Salt mismatch in cache, regenerating reMachID")
}

// Need to generate - this requires sudo
remachid, err = GenerateReMachID(salt)
if err != nil {
return "", false, err
}

// Save to cache
newCache := &CachedMachineIDs{
ReMachID:  remachid,
Salt:      salt,
CreatedAt: time.Now().Unix(),
}

// Try to preserve existing eMachID if present
if cache != nil && cache.EMachID != "" {
newCache.EMachID = cache.EMachID
newCache.ActionCount = cache.ActionCount
}

if saveErr := SaveCachedIDs(newCache); saveErr != nil {
logWarning(fmt.Sprintf("WARNING: machid - Failed to cache reMachID: %v", saveErr))
}

return remachid, false, nil
}

// GetOrGenerateEMachID attempts to load the cached eMachID, or generates a new one.
// This function does NOT require sudo since eMachID generation uses timestamps only.
//
// Parameters:
//   - salt: Salt for the machine ID
//
// Returns:
//   - The eMachID
//   - Whether the ID was loaded from cache (true) or freshly generated (false)
//   - An error if generation fails
func GetOrGenerateEMachID(salt string) (emachid string, fromCache bool, err error) {
// Try loading from cache first
cache, err := LoadCachedIDs()
if err == nil && cache.EMachID != "" {
return cache.EMachID, true, nil
}

// Generate new eMachID (no sudo required)
emachid, err = GenerateEMachID(salt)
if err != nil {
return "", false, err
}

// Save to cache (or update existing cache with eMachID)
var newCache *CachedMachineIDs
if cache != nil {
newCache = cache
newCache.EMachID = emachid
} else {
newCache = &CachedMachineIDs{
EMachID:   emachid,
Salt:      salt,
CreatedAt: time.Now().Unix(),
}
}

if saveErr := SaveCachedIDs(newCache); saveErr != nil {
logWarning(fmt.Sprintf("WARNING: machid - Failed to cache eMachID: %v", saveErr))
}

return emachid, false, nil
}

// GetOrGenerateBoth loads or generates both machine IDs.
// For reMachID, sudo is required if not cached.
// For eMachID, sudo is never required.
//
// Parameters:
//   - salt: Salt for both machine IDs
//
// Returns:
//   - CachedMachineIDs containing both IDs
//   - An error if reMachID generation fails (typically if sudo is needed but not available)
func GetOrGenerateBoth(salt string) (*CachedMachineIDs, error) {
// Try to get reMachID first (may require sudo)
remachid, reCached, err := GetOrGenerateReMachID(salt)
if err != nil {
return nil, fmt.Errorf("failed to get reMachID: %w", err)
}

// Get eMachID (never requires sudo)
emachid, eCached, err := GetOrGenerateEMachID(salt)
if err != nil {
return nil, fmt.Errorf("failed to get eMachID: %w", err)
}

// Load full cache to get action count
cache, _ := LoadCachedIDs()
actionCount := 0
if cache != nil {
actionCount = cache.ActionCount
}

result := &CachedMachineIDs{
ReMachID:    remachid,
EMachID:     emachid,
Salt:        salt,
ActionCount: actionCount,
}

// Log caching status
if reCached && eCached {
logWarning("✓ Using cached machine IDs (no sudo required)")
} else if reCached {
logWarning("✓ Using cached reMachID, generated new eMachID")
} else {
logWarning("✓ Generated and cached machine IDs")
}

return result, nil
}

// RotateEMachID generates a new eMachID and updates the cache.
// This should be called when you need to refresh the ephemeral ID.
// Does NOT require sudo.
//
// Parameters:
//   - salt: Salt for the new eMachID
//
// Returns:
//   - The new eMachID
//   - An error if generation or caching fails
func RotateEMachID(salt string) (string, error) {
// Generate new eMachID
emachid, err := GenerateEMachID(salt)
if err != nil {
return "", err
}

// Load existing cache
cache, _ := LoadCachedIDs()
if cache == nil {
cache = &CachedMachineIDs{Salt: salt}
}

// Update with new eMachID
cache.EMachID = emachid
cache.ActionCount = 0

if err := SaveCachedIDs(cache); err != nil {
return "", fmt.Errorf("failed to save rotated eMachID: %w", err)
}

return emachid, nil
}

// IncrementActionCount increments the action counter in the cache.
// Returns the new action count.
func IncrementActionCount() (int, error) {
cache, err := LoadCachedIDs()
if err != nil {
return 0, err
}

cache.ActionCount++
if err := SaveCachedIDs(cache); err != nil {
return 0, err
}

return cache.ActionCount, nil
}
