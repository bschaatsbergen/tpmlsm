# tpmlsm

![logo](logo.png "Bouncer Gopher checks every binary against the TPM list")

`tpmlsm` decides which programs may open the TPM on a Linux machine. You give it
a list of binaries, it compiles that list in, and from then on the kernel
refuses every other program that tries to open `/dev/tpm0` or `/dev/tpmrm0`,
also when it runs as root. Everything else on the machine works as before.

It's built on [eBPF](https://ebpf.io) and BPF LSM. A binary is on the list by
its path and the SHA-256 of its contents, so changing the file, or copying it
somewhere else, takes it off the list.

Here `tpm2_getrandom` is on the list. Run as root, it can still read random
bytes from the TPM, but `cat` can't open the TPM device:

```
$ sudo tpm2_getrandom --hex 8 -T device:/dev/tpmrm0
05fad09798a92bca
$ sudo cat /dev/tpm0
cat: /dev/tpm0: Operation not permitted
```

With `-watch`, `tpmlsm` stays in the foreground and logs every attempt to open
the TPM, here the allowed `tpm2_getrandom` and the refused `cat`:

```
$ sudo ./tpmlsm -watch
2026/10/04 22:35:32 allow sha256=97e1fc0f22d92de63204eec74076a003d1ca820d1d6db3c8fde3227f1ca7f4fc /usr/bin/tpm2
2026/10/04 22:35:33 enforcing until reboot; pinned to /sys/fs/bpf/tpmlsm
2026/10/04 22:35:33 watching, Ctrl-C to stop (enforcement stays)
2026/10/04 22:35:34 ALLOW pid=1130 comm=tpm2_getrandom dev=252:65536
2026/10/04 22:35:34 DENY  pid=1132 comm=cat dev=10:224
```

`tpmlsm` was prototyped during eBPF and vTPM work for a customer, where the TPM
protects the private keys used for mTLS. This repository is a reference
implementation, published alongside the blog post [A TPM bouncer in
eBPF](https://bschaatsbergen.com/posts/a-tpm-bouncer-in-ebpf/); it is not the
code that runs there.

## Running

### Requirements

`tpmlsm` requires >= 5.18 kernel, for `bpf_ima_file_hash`. It has been tested
on a 6.8 kernel.

The following kernel configuration is required.

|          Option          |                   Note                   |
| ------------------------ | ---------------------------------------- |
| CONFIG_BPF_SYSCALL=y     |                                          |
| CONFIG_DEBUG_INFO_BTF=y  |                                          |
| CONFIG_BPF_LSM=y         | must also be enabled at boot, see below  |
| CONFIG_IMA=y             | hashes the binary at exec                |

You can use `grep $OPTION /boot/config-$(uname -r)` to validate whether an
option is enabled.

BPF LSM also has to be in the active LSM list. Which LSMs are active by
default is set by `CONFIG_LSM` at build time, and many distribution kernels
leave `bpf` out. Check with:

```
cat /sys/kernel/security/lsm
```

If `bpf` is missing, append it to that list and pass the result as `lsm=` on
the kernel command line, through your bootloader's configuration, then reboot.
`lsm=` replaces `CONFIG_LSM`, so keep every LSM that is already listed.

`tpmlsm` refuses to start when BPF LSM is not active. IMA has to hash with
SHA-256; with any other algorithm every binary is denied. The upstream kernel
defaults to SHA-1, and the build-time default is in `CONFIG_IMA_DEFAULT_HASH`.
If it isn't `sha256`, also pass `ima_hash=sha256` on the kernel command line.

### Allowlist

Add every binary that may open the TPM to `allowlist.txt` as `sha256sum`
prints it, the SHA-256 followed by the file's real path, and rebuild:

```
sha256sum "$(readlink -f /usr/bin/tpm2_getrandom)" >> allowlist.txt
make
```

`tpmlsm` refuses to start with an empty or malformed allowlist. Run
`sudo ./tpmlsm` at every boot, before anything that uses the TPM, and add
`-watch` to run it in the foreground and log every allowed and denied open.
There's no command to remove it, so changing the list means building and
shipping a new `tpmlsm` and rebooting. Root can still delete its pins; see
Limitations.

### Limitations

* Allowing a binary allows everything it can do. Allowing `python3` allows
  every Python script, and since tpm2-tools 5.0 all `tpm2_*` commands are
  symlinks to one `tpm2` binary.
* Only the binary is checked, not the libraries it loads. Anyone who can start
  an allowed program can slip in code with `LD_PRELOAD`, and root also with
  `/etc/ld.so.preload` or a debugger. Prefer static binaries, such as Go built
  with `CGO_ENABLED=0`.
* Tested on ext4. On btrfs the file lookup never matches, so every TPM open is
  denied.
* Updating an allowed binary locks it out until you ship a new `tpmlsm` and
  reboot.
* Programs already running when `tpmlsm` loads are denied until they restart.
* Root can still switch `tpmlsm` off by deleting its pins, loading a kernel
  module or booting another kernel. Secure Boot and kernel lockdown (both modes
  work) make that harder. More hooks that refuse to delete the pins, unmount
  bpffs or detach the programs would close the rest while the machine runs,
  leaving a reboot as the only way. That's what you should add to properly
  harden it.

## Developing

### Dependencies

* Go >= 1.26
* LLVM/clang
* libbpf headers
* bpftool
* make

### Building

```
make
```

The generated BPF objects in `cmd/tpmlsm` are checked in, so `make` only needs
Go. It builds for the machine you're on; from macOS, `make GOOS=linux` builds
the Linux binary. To regenerate the objects after changing `bpf/tpmlsm.c`, on
Linux:

```
make generate
```

## License

The Go code is licensed under the [BSD 3-Clause License](LICENSE). The BPF
code in `bpf/` is dual-licensed under the
[GPL-2.0-only](bpf/LICENSE.GPL-2.0) and the [BSD 3-Clause License](LICENSE);
you can use the terms of either license, at your option.

## Logo Credits

The bouncer gopher is based on the Go gopher designed by Renee French.
