package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
)

type allowed struct {
	sum  [32]byte
	name string
}

// parseAllowlist reads one hex SHA-256 per line, optionally followed by a
// name, which is what sha256sum prints. Blank lines and # comments are
// skipped. Any malformed line is an error, so a typo can't silently drop a
// binary from the list.
func parseAllowlist(data []byte) ([]allowed, error) {
	var out []allowed
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hexsum, name, _ := strings.Cut(line, " ")
		var a allowed
		if len(hexsum) != 2*len(a.sum) {
			return nil, fmt.Errorf("allowlist: bad digest %q, want 64 hex characters", hexsum)
		}
		if _, err := hex.Decode(a.sum[:], []byte(hexsum)); err != nil {
			return nil, fmt.Errorf("allowlist: bad digest %q: %w", hexsum, err)
		}
		a.name = strings.TrimSpace(name)
		out = append(out, a)
	}
	return out, sc.Err()
}
