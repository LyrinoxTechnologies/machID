# MachID

**MachID** (Machine Identity, pronounced "Mock Eye Dee") is a Go library for generating unique machine identifiers on Linux systems.

## Features

- **eMachID** (Ephemeral Machine Identifier): A unique, one-time identifier that can never be regenerated
- **reMachID** (Reconstructable Machine Identifier): A reproducible identifier based on hardware that remains constant for a given machine
- Secure SHA-256 hashing
- Privacy-focused: No data is stored, only returned to the caller
- Automatic fallback from sysfs to dmidecode
- **Filesystem fallback** when hardware IDs are unavailable (with warning)
- **Strict mode** to disable filesystem fallback
- Configurable logging for warnings
- Memory clearing of sensitive data after use

## Installation

```bash
go get github.com/LyrinoxTechnologies/machID
```

## Requirements

- **Linux operating system** (uses `/sys/class/dmi/id/` and `dmidecode`)
- **Root privileges** (required to read hardware identifiers)
- **dmidecode** (optional, used as fallback if sysfs is unavailable)

```bash
# Install dmidecode on Debian/Ubuntu
sudo apt install dmidecode

# Install dmidecode on RHEL/CentOS/Fedora
sudo dnf install dmidecode
```

## Usage

### Basic Usage

```go
package main

import (
    "fmt"
    "log"

    "github.com/LyrinoxTechnologies/machID"
)

func main() {
    salt := "your-application-secret"

    // Generate an ephemeral (one-time) machine ID
    emachid, err := machid.GenerateEMachID(salt)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("eMachID: %s\n", emachid)

    // Generate a reconstructable (reproducible) machine ID
    remachid, err := machid.GenerateReMachID(salt)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("reMachID: %s\n", remachid)
}
```

### Generate Both IDs

```go
info, err := machid.GenerateBoth(salt)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("eMachID: %s\n", info.EMachID)
fmt.Printf("reMachID: %s\n", info.ReMachID)
fmt.Printf("Used Fallback: %v\n", info.UsedFallback)
```

### Check If Fallback Was Used

```go
remachid, usedFallback, err := machid.GenerateReMachIDWithInfo(salt)
if err != nil {
    log.Fatal(err)
}
if usedFallback {
    fmt.Println("Warning: Using filesystem-based machine ID (no hardware IDs available)")
}
fmt.Printf("reMachID: %s\n", remachid)
```

### Strict Mode (Disable Filesystem Fallback)

```go
// Enable strict mode - will return an error if hardware IDs are unavailable
machid.SetStrictMode(true)

remachid, err := machid.GenerateReMachID(salt)
if err == machid.ErrStrictModeNoHardwareID {
    log.Fatal("Hardware IDs required but not available")
}
```

### Custom Logger

```go
// Integrate with your logging framework
machid.SetLogger(func(msg string) {
    log.Println(msg)
})

// Or disable logging entirely
machid.SetLogger(nil)
```

### Running Your Application

Since MachID requires root privileges, run your application with sudo:

```bash
sudo go run main.go
# or
sudo ./your-compiled-binary
```

## API Reference

### Functions

#### `GenerateEMachID(salt string) (string, error)`

Generates an Ephemeral Machine Identifier. This ID is unique and can only be generated once, based on the current Unix nanosecond timestamp combined with the provided salt.

**Parameters:**
- `salt`: A non-empty string used to add entropy to the hash

**Returns:**
- A 64-character hex-encoded SHA-256 hash
- An error if root privileges are missing or salt is empty

#### `GenerateReMachID(salt string) (string, error)`

Generates a Reconstructable Machine Identifier. This ID is reproducible - the same hardware will always generate the same ID when using the same salt.

**Parameters:**
- `salt`: An optional string to add to the hash (can be empty for salt-less operation)

**Returns:**
- A 64-character hex-encoded SHA-256 hash
- An error if root privileges are missing or hardware IDs cannot be retrieved

#### `GenerateReMachIDWithInfo(salt string) (string, bool, error)`

Same as `GenerateReMachID` but also returns whether the filesystem fallback was used.

**Returns:**
- The reMachID
- `usedFallback`: true if filesystem fallback was used
- An error if generation fails

#### `GenerateBoth(salt string) (*MachIDInfo, error)`

Generates both eMachID and reMachID in a single call.

**Parameters:**
- `salt`: A non-empty string used for both identifiers

**Returns:**
- A `MachIDInfo` struct containing both identifiers and fallback status
- An error if generation fails for either identifier

#### `SetStrictMode(enabled bool)`

Enables or disables strict mode. When enabled, the library will NOT fall back to filesystem-based machine IDs and will return `ErrStrictModeNoHardwareID` instead.

#### `IsStrictMode() bool`

Returns whether strict mode is currently enabled.

#### `SetLogger(logger func(msg string))`

Sets a custom logger function for warning messages. Pass `nil` to disable logging.

#### `ClearFallbackFiles() error`

Removes the filesystem fallback files. Useful for regenerating new fallback IDs.

#### `HasFallbackFiles() bool`

Returns true if filesystem fallback files exist.

### Types

#### `MachIDInfo`

```go
type MachIDInfo struct {
    EMachID      string // Ephemeral Machine Identifier
    ReMachID     string // Reconstructable Machine Identifier
    UsedFallback bool   // True if filesystem fallback was used for reMachID
}
```

### Errors

| Error | Description |
|-------|-------------|
| `ErrNotRoot` | Library called without root privileges |
| `ErrEmptySalt` | Empty salt provided for eMachID generation |
| `ErrNoHardwareID` | Unable to retrieve hardware identifiers |
| `ErrDmidecodeNotFound` | dmidecode needed but not installed |
| `ErrStrictModeNoHardwareID` | Strict mode enabled and hardware IDs unavailable |
| `ErrFallbackFileCreation` | Failed to create filesystem fallback files |

## How It Works

### eMachID (Ephemeral Machine Identifier)

1. Captures the current Unix time in nanoseconds
2. Combines with the provided salt
3. Generates a SHA-256 hash
4. Returns the hex-encoded result

Because it uses nanosecond precision, each call produces a unique identifier that can never be regenerated.

### reMachID (Reconstructable Machine Identifier)

1. Reads hardware identifiers from sysfs:
   - `/sys/class/dmi/id/product_serial`
   - `/sys/class/dmi/id/product_uuid`
   - Fallbacks: `chassis_serial`, `board_serial`
2. If sysfs fails, falls back to `dmidecode`:
   - `system-serial-number`
   - `system-uuid`
   - Fallbacks: `chassis-serial-number`, `baseboard-serial-number`
3. If no hardware identifiers are available (and strict mode is disabled):
   - Logs a warning to stdout
   - Creates hidden files in `/etc/.machid/` with random data
   - Uses these files as the source for the machine ID
4. Combines the identifiers with optional salt
5. Generates a SHA-256 hash
6. Returns the hex-encoded result

The same hardware with the same salt will always produce the same reMachID.

## Filesystem Fallback

When the BIOS doesn't provide proper system variables (serial number/UUID), the library will:

1. **Log a warning** to stdout (or your custom logger):
   ```
   WARNING: machid - BIOS is not providing the system variables (serial/UUID) needed to generate hardware-based machine IDs.
   WARNING: machid - Falling back to filesystem-based machine IDs stored in /etc/.machid/
   WARNING: machid - These IDs will persist across reboots but are NOT tied to hardware.
   ```

2. **Create hidden files** in `/etc/.machid/`:
   - `.mserial` - Random 128-character hex string for serial
   - `.muuid` - Random 128-character hex string for UUID
   - Files have `0600` permissions (owner read/write only)
   - Directory has `0700` permissions

3. **Use these files** to generate consistent machine IDs that persist across reboots.

### Disabling Fallback (Strict Mode)

If you require hardware-based IDs only:

```go
machid.SetStrictMode(true)

_, err := machid.GenerateReMachID(salt)
if err == machid.ErrStrictModeNoHardwareID {
    // Handle the case where hardware IDs are required but unavailable
}
```

## Security Considerations

- **Root Required**: The library refuses to run without root privileges to prevent unauthorized access to hardware identifiers
- **No Storage**: No data is written to disk (except fallback files when hardware IDs unavailable)
- **Memory Clearing**: Sensitive data (hardware IDs, salt copies) are cleared from memory after hashing
- **SHA-256**: Cryptographically secure hashing prevents reverse-engineering of hardware identifiers
- **Restrictive Permissions**: Fallback files are created with `0600` permissions

## Use Cases

- **License Validation**: Use reMachID to bind software licenses to specific machines
- **Device Fingerprinting**: Identify returning devices in a fleet
- **One-Time Tokens**: Use eMachID for unique, non-reproducible tokens
- **Audit Logging**: Generate unique identifiers for audit trails

## Example

Run the included example:

```bash
cd example
sudo go run main.go
```

## License

See [LICENSE](LICENSE) for details.
