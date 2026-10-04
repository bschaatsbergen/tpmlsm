// Package tpmlsm holds the allowlist that is compiled into the tpmlsm binary.
package tpmlsm

import _ "embed"

// Allowlist is allowlist.txt as it was at build time: one hex SHA-256 per
// line, in sha256sum format. Changing it means rebuilding the binary.
//
//go:embed allowlist.txt
var Allowlist []byte
