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

// parseAllowlist parses sha256sum output: a hex SHA-256 digest and a path per
// line. Blank lines and # comments are ignored. A malformed line is an error
// rather than a skipped entry, so a typo can't silently shrink the list.
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
		if a.name == "" {
			return nil, fmt.Errorf("allowlist: digest %s has no path; use sha256sum output", hexsum)
		}
		out = append(out, a)
	}
	return out, sc.Err()
}
