// Package tpmlsm embeds the allowlist that the tpmlsm command enforces.
package tpmlsm

import _ "embed"

// Allowlist is allowlist.txt as of build time. The policy is part of the
// binary, so changing it requires a rebuild.
//
//go:embed allowlist.txt
var Allowlist []byte
