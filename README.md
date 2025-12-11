# MachID

**MachID** (Machine Identity, pronounced "Mock Eye Dee") is a Go library for generating unique machine identifiers on Linux systems.

## Features

- **eMachID** (Ephemeral Machine Identifier): A unique, one-time identifier that can never be regenerated
- **reMachID** (Reconstructable Machine Identifier): A reproducible identifier based on hardware that remains constant for a given machine
- Secure SHA-256 hashing
- Privacy-focused: No data is stored, only returned to the caller
- Automatic fallback from sysfs to dmidecode
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

#### `GenerateBoth(salt string) (*MachIDInfo, error)`

Generates both eMachID and reMachID in a single call.

**Parameters:**
- `salt`: A non-empty string used for both identifiers

**Returns:**
- A `MachIDInfo` struct containing both identifiers
- An error if generation fails for either identifier

### Types

#### `MachIDInfo`

```go
type MachIDInfo struct {
    EMachID  string // Ephemeral Machine Identifier
    ReMachID string // Reconstructable Machine Identifier
}
```

### Errors

| Error | Description |
|-------|-------------|
| `ErrNotRoot` | Library called without root privileges |
| `ErrEmptySalt` | Empty salt provided for eMachID generation |
| `ErrNoHardwareID` | Unable to retrieve hardware identifiers |
| `ErrDmidecodeNotFound` | dmidecode needed but not installed |

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
3. Combines the identifiers with optional salt
4. Generates a SHA-256 hash
5. Returns the hex-encoded result

The same hardware with the same salt will always produce the same reMachID.

## Security Considerations

- **Root Required**: The library refuses to run without root privileges to prevent unauthorized access to hardware identifiers
- **No Storage**: No data is written to disk or stored in memory longer than necessary
- **Memory Clearing**: Sensitive data (hardware IDs, salt copies) are cleared from memory after hashing
- **SHA-256**: Cryptographically secure hashing prevents reverse-engineering of hardware identifiers

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
