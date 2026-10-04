# tpmlsm

![logo](logo.png "Bouncer Gopher checks every binary against the TPM list")

`tpmlsm` decides which programs may open the TPM on a Linux machine. You give
it a list of binaries, it compiles that list in, and from then on the kernel
refuses every other program that tries to open `/dev/tpm0` or `/dev/tpmrm0`,
including programs running as root.

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

Add every binary that may open the TPM to `allowlist.txt` as `sha256sum`
prints it, the SHA-256 followed by the file's real path, and rebuild:

```
sha256sum "$(readlink -f /usr/bin/tpm2_getrandom)" >> allowlist.txt
make
```

`tpmlsm` refuses to start with an empty or malformed allowlist. Run
`sudo ./tpmlsm` at every boot, before anything that uses the TPM, and add
`-watch` to run it in the foreground and log every allowed and denied open.
Enforcement lasts until the next reboot. There is no command to remove it, so
changing the list means building and shipping a new `tpmlsm` and rebooting.

### Limitations

* An entry allows a binary, and with it everything that binary can be made
  to do. An interpreter such as `python3` runs any script it is given, and a
  multi-call binary runs every command it contains (on Ubuntu, every `tpm2_*`
  command is a symlink to one `tpm2` binary). Allow the narrowest binary that
  does the job.
* `tpmlsm` checks the binary's own file, not the shared libraries it loads,
  and anyone who can start an allowed program can make it load extra code.
  In testing, starting the allowed `tpm2_getrandom` with `LD_PRELOAD` pointing
  at another library ran that library inside the allowed process, and it
  could open the TPM. Root can do the same to every program through
  `/etc/ld.so.preload`, or attach a debugger to a running allowed process. A
  statically linked binary, such as a Go program built with `CGO_ENABLED=0`,
  loads no shared libraries, so allow static binaries where you can. Setting
  `kernel.yama.ptrace_scope=3` stops debuggers from attaching, for everyone
  including root, until the next reboot.
* Only the listed files are checked, matched by device and inode. That needs
  the device number `stat` reports to agree with the kernel's, which holds on
  ext4 (tested). btrfs reports a separate device number per subvolume, so
  there nothing matches and every open of the TPM is denied.
* An update to an allowed binary changes its hash, so it is denied until a
  `tpmlsm` with the new hash is deployed.
* A process that was already running when `tpmlsm` loaded is denied until it
  is restarted, because its hash is only checked at exec.
* The allowlist map is frozen, so it can't be changed from userspace, root
  included. Root can still remove the pins on bpffs, load a kernel module, or
  boot another kernel. Pair `tpmlsm` with Secure Boot and kernel lockdown (it
  loads under both `lockdown=integrity` and `lockdown=confidentiality`).

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
