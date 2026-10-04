// Package tpmlsm holds the allowlist that gets compiled into the tpmlsm binary.
package tpmlsm

import _ "embed"

// Allowlist is the contents of allowlist.txt at build time: one sha256sum line
// per allowed binary. Changing it means rebuilding tpmlsm.
//
//go:embed allowlist.txt
var Allowlist []byte
