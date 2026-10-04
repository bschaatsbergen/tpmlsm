// Command tpmlsm makes sure only the binaries on its allowlist can open the
// TPM, enforced in the kernel with BPF LSM. A binary counts as allowed when its
// file is on the list and the file's SHA-256 matches, so a changed binary or a
// copy somewhere else is turned away, root included. The list is compiled in
// from allowlist.txt.
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event tpmlsm ../../bpf/tpmlsm.c

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"

	"github.com/bschaatsbergen/tpmlsm"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// pinDir holds the pinned LSM links. bpffs lives in memory, so a reboot
// removes the pins and ends enforcement.
const pinDir = "/sys/fs/bpf/tpmlsm"

var tpmDevices = []string{"/dev/tpm0", "/dev/tpmrm0"}

const usage = `tpmlsm is an eBPF-based Linux kernel guard that lets only binaries in its
compiled-in allowlist use the TPM. Enforcement is pinned to /sys/fs/bpf/tpmlsm
and stays until the next reboot.

Usage:
  tpmlsm [options]   load and enforce the allowlist
  tpmlsm help        show this help

Options:
`

func main() {
	watch := flag.Bool("watch", false, "keep running and log allow and deny events until Ctrl-C")
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), usage)
		flag.PrintDefaults()
	}

	if len(os.Args) == 2 && os.Args[1] == "help" {
		flag.CommandLine.SetOutput(os.Stdout)
		flag.Usage()
		return
	}

	flag.Parse()
	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}

	if err := run(*watch); err != nil {
		log.Fatal(err)
	}
}

func run(watch bool) error {
	allowed, err := parseAllowlist(tpmlsm.Allowlist)
	if err != nil {
		return err
	}
	if len(allowed) == 0 {
		return fmt.Errorf("no hashes compiled in; add them to allowlist.txt and rebuild")
	}
	if err := checkBPFLSM(); err != nil {
		return err
	}
	// Enforcement only ends with a reboot, so a second load is a no-op.
	if _, err := os.Stat(pinDir); err == nil {
		log.Printf("already enforcing (%s exists); reboot to load a different build", pinDir)
		return nil
	}

	var objs tpmlsmObjects
	if err := loadTpmlsmObjects(&objs, nil); err != nil {
		return err
	}
	defer objs.Close()

	for _, p := range tpmDevices {
		var st unix.Stat_t
		if err := unix.Stat(p, &st); err != nil {
			return err
		}
		if err := objs.TpmDevs.Put(kdev(uint64(st.Rdev)), uint8(1)); err != nil {
			return err
		}
	}

	for _, a := range allowed {
		if err := objs.AllowedHashes.Put(a.sum, uint8(1)); err != nil {
			return err
		}
		// Exec only hashes files whose inode is in allowed_files.
		var st unix.Stat_t
		if err := unix.Stat(a.name, &st); err != nil {
			log.Printf("skip sha256=%x %s: %v", a.sum, a.name, err)
			continue
		}
		id := fileID{Ino: st.Ino, Dev: kdev(uint64(st.Dev))}
		if err := objs.AllowedFiles.Put(id, uint8(1)); err != nil {
			return err
		}
		log.Printf("allow sha256=%x %s", a.sum, a.name)
	}

	// Populate, then freeze, then attach. A frozen map can't be written from
	// userspace, root included; the BPF programs can still read it.
	if err := objs.AllowedHashes.Freeze(); err != nil {
		return err
	}
	if err := objs.AllowedFiles.Freeze(); err != nil {
		return err
	}
	if err := objs.TpmDevs.Freeze(); err != nil {
		return err
	}

	progs := map[string]*ebpf.Program{
		"on_exec":  objs.OnExec,
		"on_fork":  objs.OnFork,
		"tpm_open": objs.TpmOpen,
	}
	if err := os.MkdirAll(pinDir, 0o700); err != nil {
		return err
	}
	for name, prog := range progs {
		if err := attach(name, prog); err != nil {
			os.RemoveAll(pinDir)
			return fmt.Errorf("attach %s: %w", name, err)
		}
	}
	log.Printf("enforcing until reboot; pinned to %s", pinDir)

	if !watch {
		return nil
	}
	return watchEvents(objs.Events)
}

// attach attaches prog as an LSM program and pins the link, so it stays
// attached after this process exits.
func attach(name string, prog *ebpf.Program) error {
	l, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		return err
	}
	defer l.Close()
	return l.Pin(filepath.Join(pinDir, name))
}

// checkBPFLSM fails if BPF LSM isn't active. Without it the programs attach
// without error and never run.
func checkBPFLSM() error {
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return err
	}
	lsms := strings.TrimSpace(string(b))
	if slices.Contains(strings.Split(lsms, ","), "bpf") {
		return nil
	}
	return fmt.Errorf("BPF LSM is not enabled (active: %s); add bpf to lsm= on the kernel command line", lsms)
}

// fileID matches struct file_id in bpf/tpmlsm.c.
type fileID struct {
	Ino uint64
	Dev uint32
	_   uint32
}

// kdev converts a device number from stat's encoding to the kernel's,
// major<<20 | minor. The BPF programs compare against the kernel's, so a
// value straight from stat would never match.
func kdev(dev uint64) uint32 {
	return unix.Major(dev)<<20 | unix.Minor(dev)
}

func watchEvents(m *ebpf.Map) error {
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		return err
	}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
		rd.Close()
	}()

	log.Println("watching, Ctrl-C to stop (enforcement stays)")
	for {
		rec, err := rd.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil
		}
		if err != nil {
			return err
		}
		var e tpmlsmEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &e); err != nil {
			return err
		}
		verdict := "DENY "
		if e.Allowed == 1 {
			verdict = "ALLOW"
		}
		log.Printf("%s pid=%d comm=%s dev=%d:%d", verdict,
			e.Pid, unix.ByteSliceToString(e.Comm[:]), e.Dev>>20, e.Dev&0xfffff)
	}
}
