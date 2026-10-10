# Next Session: 20-Link Voider Stress Test

Use this file as the operating handoff for the next Codex/GPT session.

## Starting State

- Repository: `/home/dollner/Desktop/voider-v2`
- Read `AGENTS.md` first and obey it.
- Current marker commit/tag:
  - commit: `ef90aaa`
  - tag: `perhaps-we-overdid-a-thing-that-was-working-and-now-its-borked`
- The flashable image was built from `3d50ab9`, which includes:
  - reboot support
  - per-connection reset
  - precise transport labels
  - LAN6 fix
  - role-separated 506 mailbox model
- The role-separated mailbox implementation is:
  - client-role accounts: `vmc002..vmc254`
  - server-role accounts: `vms002..vms254`
  - runtime chroots: `/var/sftp/clients/vmbNNN` and `/var/sftp/servers/vmbNNN`
  - shell: `/sbin/nologin`
  - mailbox authorized keys: `/etc/voider/certs/mailboxes/%u.authorized_keys`
  - `/var/sftp` is RAM-backed runtime state
  - accounts are fixed installed SYSTEM structure
  - pairing keys/config/secrets are curated STATE
- Final image paths:
  - third Pi: `/home/dollner/voider-build-3d50ab9/release/voider-aarch64-3d50ab9.img.gz`
  - local copy: `/home/dollner/Desktop/voider-v2/release/mailbox-roles-20261004/voider-aarch64-3d50ab9.img.gz`
- Image checksum:
  - `b35970bb7b8060a9cca47753876925a3a1efdf1dee9b53b6f035c9dd7d4be8f1`
- Final image validation already passed:
  - exact raw size `940572672`
  - partition/layout audit
  - identity/credential-clean audit
  - disposable loop flash safety with full readback and SSH-key injection
- Compact backups exist on both USB drives:
  - `/media/dollner/External HD/Backups/voider-v2-20261004T122653Z-ef90aaa-compact-backup.tar.gz`
  - `/media/dollner/96f872c0-fece-4b7f-9501-3531efa3f271/backups/voider-v2-20261004T122653Z-ef90aaa-compact-backup.tar.gz`
  - checksum: `af82af9a3e28f539bd6de165752b33497ffbe568c512ed8efc6cfe074b0c1fe6`

## Hardware/Test Rules

- Use the third Pi at `dollner@192.168.178.83` as the harness.
- Appliance management SSH is `root` through the harness namespaces, using `.voider-dev/ssh_pi_ed25519` and `.voider-dev/ssh-netns-proxy`.
- Do not use phone calls for this stress test. Use tunnel pings.
- Do not reboot either appliance unless the user explicitly approves.
- Appliance binary overlays vanish on reboot.
- Always use `make -j2` on Raspberry Pis.
- Preserve device identities and healthy selected transports.
- Do not introduce compatibility fallback for old pairings.

## Goal

After both Voiders are flashed with the new image and installed, create and validate a 20-link test constellation between the two boxes:

- On each Voider box:
  - 10 client-side pairings
  - 10 server-side pairings
- Across the two-box constellation:
  - all 20 links must use the same selected transport type for the test run
  - choose one available transport type deliberately, then keep the constellation constrained to that type
  - do not mix Tor/direct/LAN/hole-punch within the same 20-link stress run
- Stress-test selected-connection resets:
  - reset one selected link at a time
  - verify that the selected link recovers
  - verify that the other 19 links stay healthy
  - repeat across representative client-role and server-role slots on both boxes
- Select exactly one available path on both appliances, then run
  `scripts/voider-ladder PATH` on the workstation (`lan4`, `lan6`, `direct4`,
  `direct6`, `hp4`, `hp6`, or `tor`). The script prepares the third Pi and
  both VPSs, discovers the actual cable-side boxes and configured ports,
  and refuses mismatched appliance path settings. `--watch` repeats status;
  `status` reads once; `cleanup` restores ordinary remote NAT.
- Every remote profile retains IPv4 Internet, DNS, UDP/123 Chrony, and
  outbound TCP for Tor/CAP2. IPv6 profiles add routing/RA without blocking
  IPv4. Chrony must report synchronized before network verification passes.
  Profiles are runtime-only: rerun after a harness/VPS restart.
- Use tunnel pings as the health signal.

## Important Clarification

The desired test shape is not "only 10 servers" or "only 10 clients". It is:

```text
Box A: 10 client links + 10 server links
Box B: 10 client links + 10 server links
Total active two-box relationships under test: 20 links
```

The mailbox-role model should be validated by confirming that client-role and server-role material do not collide:

```text
client-role accounts use vmcNNN and /var/sftp/clients/vmbNNN
server-role accounts use vmsNNN and /var/sftp/servers/vmbNNN
```

The same numeric slot may exist in both roles, but role plus slot must select distinct account/key/chroot paths.

## Suggested Procedure

1. Read `AGENTS.md` and this file.
2. Confirm both appliances are running the newly flashed/install-completed `3d50ab9` image.
3. Verify identity-clean install state and management SSH access through the harness.
4. Verify the 506 mailbox account/chroot model on both appliances:
   - accounts exist: `vmc002..vmc254`, `vms002..vms254`
   - `/var/sftp` is runtime/RAM-backed
   - mailbox key directory is curated STATE-backed
   - dormant mailboxes have no authorized key
5. Build or use existing harness helpers to create the 20 pairings.
6. Ensure all 20 links converge to the same transport type for the chosen run.
7. Use the workstation ladder script for the selected path; it reads every
   configured WireGuard port rather than assuming slot 2. Separate fallback
   fault injection is outside this path-preparation workflow.
8. Establish baseline tunnel-ping health for all 20 links.
9. For each selected reset case:
   - capture pre-reset selected transport and ping health
   - reset exactly one selected connection
   - verify that link returns healthy on the chosen transport type
   - verify the other 19 links stay healthy
   - collect concise evidence
10. Summarize results with:
   - slots and roles tested
   - selected transport type
   - reset outcomes
   - unaffected-link health
   - any failures with exact logs/commands

## Things Not To Do

- Do not test by placing phone calls.
- Do not reboot without asking.
- Do not mutate identities except through intended fresh install/pairing flow.
- Do not accept mixed transport convergence for this specific stress run.
- Do not claim the 506 mailbox model is proven until the flashed image is checked on the live appliances.
- Do not use `make -j4` or higher on Raspberry Pis.
