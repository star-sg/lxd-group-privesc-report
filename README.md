# LXD Root

Local Privilege Escalation to **root** via default `lxd` group membership and the
`lxd-installer` package on Ubuntu.

![Demo: privilege escalation from an unprivileged lxd-group user to root](asset/demo.gif)


> Demo runs on AWS EC2 Ubuntu Server 26.04

The bug is that Ubuntu Server 26.04's default install silently grants the
primary user membership in the `lxd` group, a group that by LXD's trust model
equals passwordless root, while presenting it as an innocuous "container
management" capability. Moreover, that unprivileged user can install and set up
LXD on their own, without any additional privilege, so the root-equivalent
group is reachable end to end without ever touching the `sudo` password.

## Am I affected?

A host is exposed when both are true: someone unprivileged is in the `lxd`
group, and a root-run LXD path (an installed daemon, or the `lxd-installer`
socket) is reachable.

Check and run [`poc/check-vulnerable.sh`](poc/check-vulnerable.sh):

```bash
cd poc && chmod +x check-vulnerable.sh && ./check-vulnerable.sh
```

## LPE PoC

```bash
cd poc && chmod +x exploit.sh && ./exploit.sh # run as an unprivileged user in the lxd group
```

See [`poc/README.md`](poc/README.md) for requirements, expected output, manual
reproduction, and cleanup.

## Suggested mitigation

The fix is on the distro side: Ubuntu Server should not place the primary user in
the `lxd` group by default. That group is root-equivalent, so it deserves the
same explicit, understood grant as `sudo`, not a silent default. Requiring the
`sudo` password before the on-demand `lxd-installer` runs would also close the
pre-install vector, but on its own it leaves an already-installed LXD exposed.

### Temporary patch

Until that lands, remove every unprivileged account from the `lxd` group. The
change takes effect on the member's next login.

```bash
getent group lxd               # list current members
sudo gpasswd -d "$USER" lxd    # remove one member; repeat for each
```

Then treat `lxd` membership like passwordless `sudo`: grant it only to users you
already trust with root.

## Credits

- [**Weiming Shi**](https://bestwing.me) ([`swing`](https://github.com/winmin)) — STAR Labs SG Pte. Ltd.
- [**n132**](https://github.com/n132)

## Disclaimer

We responsibly disclosed this issue to the Ubuntu Security team and, following their review, it was determined not to constitute a security vulnerability.

This material is provided solely for authorized security research, testing, and educational purposes. It should only be used on systems that you own or for which you have obtained explicit permission to assess. The authors assume no responsibility or liability for any misuse, damage, or consequences arising from the use of this information.
