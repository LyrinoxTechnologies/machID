// Example program demonstrating the machID library usage.
// This must be run with root privileges (sudo).
package main

import (
"fmt"
"os"

"github.com/LyrinoxTechnologies/machID"
)

func main() {
fmt.Println("MachID - Machine Identification Library Demo")
fmt.Println("=============================================")
fmt.Println()

// Define a salt for the identifiers
// In production, use a unique salt per application
salt := "my-application-secret-salt-2024"

// Generate an Ephemeral Machine ID
fmt.Println("Generating eMachID (Ephemeral Machine Identifier)...")
emachid, err := machid.GenerateEMachID(salt)
if err != nil {
fmt.Fprintf(os.Stderr, "Error generating eMachID: %v\n", err)
os.Exit(1)
}
fmt.Printf("eMachID: %s\n", emachid)
fmt.Println("(This ID is unique and will never be generated again)")
fmt.Println()

// Generate a Reconstructable Machine ID with info about fallback usage
fmt.Println("Generating reMachID (Reconstructable Machine Identifier)...")
remachid, usedFallback, err := machid.GenerateReMachIDWithInfo(salt)
if err != nil {
fmt.Fprintf(os.Stderr, "Error generating reMachID: %v\n", err)
os.Exit(1)
}
fmt.Printf("reMachID: %s\n", remachid)
fmt.Println("(This ID will be the same every time on this machine)")
if usedFallback {
fmt.Println("⚠️  Note: Using filesystem-based fallback (no hardware IDs available)")
}
fmt.Println()

// Generate a second eMachID to demonstrate uniqueness
fmt.Println("Generating another eMachID to show uniqueness...")
emachid2, err := machid.GenerateEMachID(salt)
if err != nil {
fmt.Fprintf(os.Stderr, "Error generating second eMachID: %v\n", err)
os.Exit(1)
}
fmt.Printf("eMachID (2nd): %s\n", emachid2)
fmt.Printf("Different from first: %v\n", emachid != emachid2)
fmt.Println()

// Generate a second reMachID to demonstrate reproducibility
fmt.Println("Generating another reMachID to show reproducibility...")
remachid2, err := machid.GenerateReMachID(salt)
if err != nil {
fmt.Fprintf(os.Stderr, "Error generating second reMachID: %v\n", err)
os.Exit(1)
}
fmt.Printf("reMachID (2nd): %s\n", remachid2)
fmt.Printf("Same as first: %v\n", remachid == remachid2)
fmt.Println()

// Demonstrate GenerateBoth
fmt.Println("Using GenerateBoth to get both IDs at once...")
info, err := machid.GenerateBoth(salt)
if err != nil {
fmt.Fprintf(os.Stderr, "Error generating both IDs: %v\n", err)
os.Exit(1)
}
fmt.Printf("eMachID:      %s\n", info.EMachID)
fmt.Printf("reMachID:     %s\n", info.ReMachID)
fmt.Printf("UsedFallback: %v\n", info.UsedFallback)
fmt.Println()

// Demonstrate strict mode
fmt.Println("Testing strict mode...")
machid.SetStrictMode(true)
_, err = machid.GenerateReMachID(salt)
if err == machid.ErrStrictModeNoHardwareID {
fmt.Println("Strict mode correctly blocked filesystem fallback")
} else if err != nil {
fmt.Printf("Error in strict mode: %v\n", err)
} else {
fmt.Println("Strict mode: Hardware IDs are available, no fallback needed")
}
machid.SetStrictMode(false)
}
