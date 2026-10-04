# tpmlsm

![logo](logo.png "Bouncer Gopher checks every binary against the TPM list")

`tpmlsm` is an [eBPF](https://ebpf.io)-based Linux kernel guard that lets only
allowlisted binaries use the TPM. A binary is identified by the SHA-256 of its
file, not by its PID, name or path, so a renamed copy is allowed and a modified
one is denied. Root is no exception.

The allowed hashes are compiled into the `tpmlsm` binary. Build it from the
same release as the binaries it allows, and anything deployed outside that
release is denied.

The following example allows `tpm2_getrandom`, after which root can still read
random bytes from the TPM but `cat` is denied:

```
$ sudo ./tpmlsm
2026/10/04 22:13:06 allow sha256=97e1fc0f22d92de63204eec74076a003d1ca820d1d6db3c8fde3227f1ca7f4fc /usr/bin/tpm2
2026/10/04 22:13:06 enforcing; pinned to /sys/fs/bpf/tpmlsm, run 'tpmlsm unload' to remove
2026/10/04 22:13:06 watching, Ctrl-C to stop (enforcement stays)
2026/10/04 22:13:08 ALLOW pid=2026 comm=tpm2_getrandom dev=252:65536
2026/10/04 22:13:08 DENY  pid=2028 comm=cat dev=10:224
```

It is a reference implementation, written alongside the blog post
[A TPM bouncer in eBPF](https://bschaatsbergen.com/posts/a-tpm-bouncer-in-ebpf/).

## Running

### Requirements

`tpmlsm` requires >= 5.18 kernel, for `bpf_ima_file_hash`. It has been tested
on Ubuntu 24.04 with `6.8.0-146-generic`.

The following kernel configuration is required.

|          Option          |                   Note                   |
| ------------------------ | ---------------------------------------- |
| CONFIG_BPF_SYSCALL=y     |                                          |
| CONFIG_DEBUG_INFO_BTF=y  |                                          |
| CONFIG_BPF_LSM=y         | must also be enabled at boot, see below  |
| CONFIG_IMA=y             | hashes the binary at exec                |

You can use `grep $OPTION /boot/config-$(uname -r)` to validate whether an
option is enabled.

BPF LSM also has to be in the active LSM list, which on Ubuntu it is not by
default. Check with:

```
cat /sys/kernel/security/lsm
```

If `bpf` is missing, append it to that list and pass it as `lsm=` on the kernel
command line. On Ubuntu:

```
echo 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT lsm=lockdown,capability,landlock,yama,apparmor,bpf ima_hash=sha256"' | sudo tee /etc/default/grub.d/99-tpmlsm.cfg
sudo update-grub && sudo reboot
```

`tpmlsm` refuses to start when BPF LSM is not active. IMA has to hash with
SHA-256 (`ima_hash=sha256`, the default on Ubuntu); with any other algorithm
every binary is denied.

### Allowlist

Add the SHA-256 of every binary that may open the TPM to `allowlist.txt`, one
per line (`sha256sum` output works as is), and rebuild:

```
sha256sum "$(readlink -f /usr/bin/tpm2_getrandom)" >> allowlist.txt
make
```

`tpmlsm` refuses to start with an empty or malformed allowlist. Changing the
list means building and shipping a new `tpmlsm`.

### Usage

```
$ ./tpmlsm -h
Usage: tpmlsm [options]
       tpmlsm unload

Options:
  -guard
    	also deny detaching links and loading LSM programs through bpf()
  -watch
    	log allow and deny events until Ctrl-C; enforcement stays after exit (default true)
```

Enforcement is pinned to `/sys/fs/bpf/tpmlsm` and stays after `tpmlsm` exits.
Remove it with `sudo ./tpmlsm unload`, or reboot.

### Limitations

* On Ubuntu every `tpm2_*` command is a symlink to one `tpm2` binary, so
  allowing one allows all of them. The same goes for interpreters: allowing
  `python3` allows every Python script.
* An update to an allowed binary changes its hash, so it is denied until a
  `tpmlsm` with the new hash is deployed.
* A process that was already running when `tpmlsm` loaded is denied until it
  is restarted, because its hash is only checked at exec.
* The allowlist map is frozen, so it can't be changed from userspace, root
  included. `-guard` additionally denies detaching the links through `bpf()`,
  but root can still remove the pins with `rm` on bpffs, load a kernel module,
  or boot another kernel. Pair it with Secure Boot and kernel lockdown, and
  bind TPM keys to PCRs that measure the loader.

## Developing

### Dependencies

* Go >= 1.26
* LLVM/clang
* libbpf headers (`libbpf-dev`)
* bpftool (`linux-tools`)
* make

On Ubuntu:

```
sudo apt-get install -y clang llvm libbpf-dev golang-go linux-tools-$(uname -r) linux-tools-common make
```

### Building

```
make
```

The generated BPF objects in `cmd/tpmlsm` are checked in, so `make` only needs
Go and works on macOS too (it builds for Linux). To regenerate them after
changing `bpf/tpmlsm.c`, on Linux:

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
