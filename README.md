# tpmlsm

![logo](logo.png "Bouncer Gopher checks every binary against the TPM list")

`tpmlsm` is an [eBPF](https://ebpf.io)-based Linux kernel guard that lets only
allowlisted binaries use the TPM. A binary is identified by the SHA-256 of its
file, not by its PID, name or path, so a renamed copy is allowed and a modified
one is denied. Root is no exception.

The allowed hashes are compiled into the `tpmlsm` binary. Build it from the
same release as the binaries it allows, and anything deployed outside that
release is denied.

`tpmlsm` only checks opens of `/dev/tpm0` and `/dev/tpmrm0`. Every other file,
and every program that doesn't touch the TPM, works as before.

The following example has the hash of `tpm2_getrandom` compiled in. Run as
root, `tpm2_getrandom` can still read random bytes from the TPM, but `cat`
can't open the TPM device:

```
$ sudo tpm2_getrandom --hex 8 -T device:/dev/tpmrm0
05fad09798a92bca
$ sudo cat /dev/tpm0
cat: /dev/tpm0: Operation not permitted
```

With `-watch`, `tpmlsm` logs both attempts:

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

### IMA policy

`tpmlsm` gets each binary's SHA-256 from IMA at exec. Without an IMA policy,
which is the default, IMA hashes the whole file on every exec and keeps
nothing, so every program start on the machine pays for reading and hashing
its binary, and larger binaries pay more.

Load a policy that measures executables, and IMA keeps each hash until the
file changes, so an unchanged binary is hashed once. systemd loads
`/etc/ima/ima-policy` at boot:

```
sudo mkdir -p /etc/ima
echo 'measure func=BPRM_CHECK mask=MAY_EXEC' | sudo tee /etc/ima/ima-policy
```

The policy takes effect at the next boot; the kernel accepts one policy per
boot. Prefer it over the built-in `ima_policy=tcb`, which also measures every
file root reads, so a file that keeps changing, such as a log, is measured
again after every change and the measurement list keeps growing.

### Allowlist

Add the SHA-256 of every binary that may open the TPM to `allowlist.txt`, one
per line (`sha256sum` output works as is), and rebuild:

```
sha256sum "$(readlink -f /usr/bin/tpm2_getrandom)" >> allowlist.txt
make
```

`tpmlsm` refuses to start with an empty or malformed allowlist. Run
`sudo ./tpmlsm` at every boot, before anything that uses the TPM, and add
`-watch` to keep it running and log every allowed and denied open.
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
* An update to an allowed binary changes its hash, so it is denied until a
  `tpmlsm` with the new hash is deployed.
* A process that was already running when `tpmlsm` loaded is denied until it
  is restarted, because its hash is only checked at exec.
* The allowlist map is frozen, so it can't be changed from userspace, root
  included. Root can still remove the pins on bpffs, load a kernel module, or
  boot another kernel. Pair `tpmlsm` with Secure Boot and kernel lockdown (it
  loads under both `lockdown=integrity` and `lockdown=confidentiality`), and
  use remote attestation of the IMA log in PCR 10 to check that it loaded.

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
