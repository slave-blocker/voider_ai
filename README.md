# Voider

Voider is a two-appliance private phone link for supported Ethernet phones. Its
outcome is a phone call, not a general networking platform. Each appliance owns
the phone-side `172.16.19.84/30` link: Voider is `172.16.19.86`, the expected
factory-reset phone is `172.16.19.85`, and readiness is carrier plus ping. The
phone web UI is never part of installation or operation.

Voider always tries authenticated offline LAN discovery first, then CAP2
coordinates direct WireGuard, WireGuard hole punch, and Tor fallback. CAP2 uses
separate pair-authenticated, correlated offer/answer records; LAN discovery uses the per-pair secret
and is completed only by a WireGuard handshake and successful tunnel ping. The phone/call plane
remains IPv4; IPv6 is an optional outer WireGuard underlay. Voider uses Alpine,
OpenRC, and no libp2p.

`peerd` runs one worker per saved client or server relationship. A failed ping
blocks only that worker; the coordinator publishes status about once a second.
WireGuard goes offline after three failed probes, normally in roughly 17 seconds.
The UI expires status after five seconds without a fresh publication. Workers
recover usable authenticated WireGuard tunnels while waiting for CAP2, and
connected clients keep answering CAP2 for the other end. Healthy selections
stay selected until they fail, are disabled, or the user requests a retry.
At most eight initiating CAP2 exchanges run simultaneously on each appliance.
Rebuilding hundreds of connections after a complete outage still takes minutes
through Tor/SFTP; the health and UI update time does not grow with that queue.

## Release status

### Service ownership — 2026-10-10

OpenRC supervises the display, buttons, WAN/phone monitors, Tor, sshd,
the root SIP translator, and the connection coordinator directly. Crash retries
are bounded; coordinator, SIP, display, and WAN/phone loops have application
heartbeat checks. The integrity gate and fail-closed firewall precede network
services. The firewall outlives coordinator restarts.

`peerd` alone owns CAP2/hole-punch jobs, Tor tunnel workers, and per-server
namespace SIP translators. Children stop with their owner; reset/removal uses
acknowledged, role-specific teardown. SIP queues never bypass a missing
translator, and stale translator/WAN/phone status cannot advertise readiness.
Healthy transport selections remain sticky, including across WAN changes.
LAN discovery continues while remote negotiation waits for local clock sync.

Display and SSH actions share one backend action lock. Management SSH changes
touch only its admission rules, not the call plane or SFTP service. WAN address
changes invalidate discovery caches without restarting Tor. Once this boot has
synchronized, every subsequent Chrony execution uses slew-only restart mode.
Chrony retains its native self-backgrounding startup handshake and prepares its
RAM command-socket directory. Tor hard-depends on successful Chrony startup;
its supervised launcher retries bounded clock-readiness checks until time is
ready, without failing startup on a temporary NTP outage or blocking the other
providers. Once launched, Tor is not restarted merely because NTP disappears.
The installer stages provider services only after generating factory identity.

Do not flash `release/voider-aarch64-chrony-tor-20261010.img.gz`: its automated
checks missed the Chrony/Tor startup-readiness regression.

New images from this work are test candidates until both physical installations
and real-call recovery checks pass; software/image audits do not replace those
checks.

### USB workflow rewrite — 2026-09-21

SHARE and BACKUP select exactly one safe removable stick and require held
confirmation before replacing its entire partition layout. Output is synced,
unmounted, reopened read-only and verified before safe removal. ADD and RESTORE
read and validate without changing the stick. Existing bundle/backup formats
remain compatible. System disks, mounted media, active holders/swap and changed
insertions are rejected; existing partition count is never an erase veto.

ADMIN has one contextual LOGIN KEY action: confirm creation or replacement,
insert a stick, confirm whole-stick erasure, then receive a verified new key pair.
Only the public half is installed. Private generation uses a private RAM directory;
USB failure retains the old login key and access state. SSH ON/OFF and permanent
key removal remain separate confirmed actions.

RESTORE validates before confirmation, saves through the same checked STATE
transaction as other changes, and blocks stale RAM saves until an explicit
restart. Record the new check code, remove the stick, then hold RESTART to apply.
Later boots retain MATCH / DIFFER. No restart happens automatically.

Host and native Alpine/aarch64 release suites pass. USB checks cover synthetic
failure injection and disposable real loop devices with blank, single-partition,
multi-partition MBR and GPT layouts. UI checks cover 129 button journeys, all
50 pages and three languages; the four rebuilt manuals pass layout review.

Audited release source: `2a009d69694a58efd57fb7e33af1c8bed2ed9357`.
The workstation image is `release/voider-aarch64-2a009d69694a.img.gz`, with
metadata and checksum sidecars. Its raw size is exactly 940,572,672 bytes.
Native image audit, disposable-loop flashing (including complete readback and
public-key injection), and independent workstation verification passed.
Compressed SHA256: `9c1c3a807e332f40153376137eb61ec3a4591b1932ef51a9c5c5b7ebd2eee37a`.
Raw SHA256: `7c828216da595092d7f0c98b797d20cd63fc9503150b1d47840d595199d2d220`.
Validation logs and package inventory are in `release/verification-usb-2a009d69694a/`.
Later documentation commits do not change this image's recorded source revision.

Software and native disposable-media validation are separate from physical USB
acceptance. The original stick/port path had kernel protocol, enumeration and I/O
errors; their cause remains unresolved. The multi-partition correction does not
establish hardware reliability. Both installed appliances were rediscovered via
the existing harness and their pinned host keys; USB/UI/main still match release
`f465247aa03d`, both report zero connections. Their state was not modified.

Current test evidence and rollback details remain in the existing ignored
[evidence record](.voider-dev/remote-path-stage/reconnect-20260913/evidence.md)
and [rollback record](.voider-dev/remote-path-stage/pi/rollback.txt).

The source tree implements the display-required installer, optional persistent
management SSH, and two-step integrity model described below. A physical-test
image is flash-ready only when its commit-stamped filename, checksum, metadata,
and archived source revision all agree after host and native Alpine release tests. It must
still pass both real display installations, including management SSH on/off and
post-reboot tests, before publication.

Physical checkpoint, 2026-09-13: the `168a6cc` release image passed two real
display installations, one requested reboot per appliance, identity and
read-only integrity checks, independent RTC-less NTP synchronization before
CAP2, normal physical pairing, authenticated common HP4 selection, isolated
dual-path packet proof, and real calls with two-way audio in both directions.
Publication remains blocked on the remaining automatic reconnection matrix and
the 60-minute Tor-only stability gate.

The post-OPSEC call firewall keeps SIP and media confined to the exact fixed
phone identity and Voider-owned call interfaces, but follows the UDP ports the
phones actually negotiate in SDP instead of assuming RTP is always in
`10000:20000`; supported GXP phones commonly select port `5004`. A populated
CONNECTIONS screen retains SHARE and ADD so additional relationships can be
created, while PREV/NEXT remain on the opened connection. A confirmed shutdown
now shows POWERING OFF, saves curated state, paints the mandatory panel black,
requests panel power-down, and only then invokes system poweroff.

Release `fde4576` is rejected. Its mailbox-account refactor tried to create a
slot account during SHARE after SYSTEM was sealed read-only, so both appliances
failed before writing the USB key. Installation now creates the fixed
role-separated `vmc002`–`vmc254` and `vms002`–`vms254` account sets before
sealing. Their RAM-backed chroots are `/var/sftp/clients/vmbNNN` and
`/var/sftp/servers/vmbNNN`. Normal pairing only adds the slot's curated
key/configuration/secrets; removal clears its volatile records and key while
leaving the fixed empty chroot and inert `nologin` account. Dormant accounts
have no authorized key, and factory reset never modifies the immutable account
database.

The old image under `candidate/` remains rejected and must not be used: real
pairing exposed a USB mountpoint under the sealed read-only system. Installed
test appliances could be repaired through curated STATE without a reboot; the
corrected release image includes the runtime USB mount fix and passed SHARE/ADD
on both physical appliances.

The same physical test also exposed diagnostic output preceding the USB bundle
fingerprint. The importer must select the validated 64-character fingerprint
line and distinguish a missing, invalid, or unreadable bundle; treating the
first diagnostic line as the fingerprint produced a false `NO BUNDLE` result.

A third rejection is semantic: fingerprint-derived names and `172.16.x.x` dial
instructions conflated a persistent contact identity with the master Voider's
anonymous incoming-call disguise. Connections use neutral local labels. The
server appliance dials client slot `s` as `10.1.s.1`; the client appliance dials
local server slot `X` as `10.X.1.1`. Per-boot fake `172.16.x.x` addresses remain
strictly an incoming caller presentation and are never shown as dial targets.

Remote-path testing exposed two more bootstrap defects. CAP2 SFTP called the
optional, absent `torsocks` command even though the image already includes
OpenSSH and SOCKS-capable OpenBSD `nc`; it now uses that required path directly.
Also, Alpine's DHCP hook tried to create `/etc/resolv.conf` after SYSTEM was
sealed, leaving chrony without DNS, the Pi clock at 1970, and Tor unable to
bootstrap. DHCP resolver output now lives at `/run/resolv.conf`, reached through
a sealed `/etc/resolv.conf` symlink. A later RTC-less boot exposed a second
clock edge case: DNS became available only after chronyd's one-shot startup
step had passed. Chrony now permits a large correction only during its first
five valid updates, and remote CAP2 waits until that appliance is synchronized
to its own selected NTP source. No pairwise clock comparison or packet-delay
threshold is used. These conditions are regression-tested.

## Tor transport (wire v8)

Upgrade **both appliances together** for Tor. Existing pairing bundles, USB
fingerprints, keys and curated STATE remain valid; re-pairing is unnecessary.
The executable retains the `tundup-v7-secure` name, but accepts only wire v8.
The existing wire-v8 fp-only format (identifier 3) is preserved. Older wire
versions and encrypted v8 formats fail closed; an old fp-only peer remains wire
compatible. Update tundup and its peerd launcher together on each appliance:
obsolete cipher/stream command arguments are rejected. LAN and WireGuard are unchanged.

Every relationship targets exactly two bidirectional Tor TCP streams. Each
logical TUN packet is sealed once and copied to both usable streams; the first
valid authenticated sequence is delivered and subsequent copies are discarded.
A missing stream reconnects independently with 0.5–8 second exponential backoff
plus a fixed per-stream offset. A single usable stream carries traffic immediately.
Total stream loss retires the session, cancels pending handshakes and generates
a new epoch; reconnection starts a fresh session. This never restarts Tor.
Legacy `TUNDUP_MODE`, `TUNDUP_AEAD`, `TUNDUP_CIRCUITS`, `TUNDUP_STREAMS` and
`TUNDUP_SCHED` global settings are accepted without selecting behavior. Old peer
and USB `TUNMODE`, `TUNDUP_MODE`, `AEAD`, `HW_AES`, `STREAMS` and `SCHED` fields
are ignored. No migration rewrites existing STATE, secrets or bundle identity.
CAP2 keeps fixed `TUNMODE=fp-only`, `AEAD=none`, `SCHED=dup` descriptors for
older v8 peers; these are compatibility facts, not selectable settings.

Each process generates a 256-bit random epoch. Each stream handshake exchanges
fresh 256-bit challenges and HMAC-SHA-256 proofs with distinct server, client and
acceptance labels. The authenticated transcript includes the wire version,
fixed format, stream index, both epochs and both challenges. HKDF-SHA-256 binds
the existing PSK bytes to the registered USB fingerprint, then derives separate
client-to-server and server-to-client keys and a session identifier from both
epochs. Additional streams must authenticate to the same active session and a
vacant stream index; they cannot replace a healthy stream. Old pending proofs
cannot revive a retired epoch.

Tundup provides authenticated plaintext only; **Tor provides encryption**.
There is no tundup cipher selection or payload encryption implementation.
Each directional session has one monotonically increasing 64-bit packet counter,
starting at one. Fresh session keys separate restarts, total-loss recovery and
directions. A surviving session retains its counter across individual stream
reconnects. Identical copies retransmit the same authenticated frame. Sequence
exhaustion or a cryptographic API failure stops the transport.

Directional HMAC-SHA-256 authenticates the entire plaintext frame, including the
44-byte header (length, type, fixed format, session, sequence), along
with the payload. Payloads are at most 4,096 bytes. Replay admission happens only
after successful authentication, using a fixed 1,024-sequence window that permits
reordering; corrupt first arrivals cannot suppress valid second copies. Old or
out-of-window packets are dropped regardless of payload equality.

A single nonblocking poll loop owns all descriptors. There are at most six TCP
connections (two active plus four pending), 32 queued packets per stream, a
250 ms unsent queue-age limit, a one-second output deadline, a three-second
partial-frame input deadline and a 45-second total connect/handshake deadline.
An expired partial write closes that stream instead of corrupting TCP framing.
Authenticated heartbeats run every five seconds; 20 seconds without new valid
traffic closes a stalled stream. Kernel socket buffers are bounded separately.
Admission is limited to ten connections/second; work per descriptor is bounded.
After complete loss, peer supervision gives the existing tundup worker its
90-second Tor proof window to recover. This covers asymmetric disconnect
notification and expiry of old streams before a new epoch can be accepted.
Failure beyond that window follows the existing CAP2 retry lifecycle.
Logs have a fixed diagnostic budget. `/run/voider/tundup-TUN.status` provides
active streams, per-stream copies, reconnects, duplicates, expiry and rejection
counters without UI settings or secret material.

SOCKS authentication is mandatory. A fresh random token on each connection plus
the stream index isolates streams, relationships and retries, so a reconnect
does not reuse the same impaired circuit; Tor's `IsolateSOCKSAuth` is
explicit on both managed SOCKS listeners. Tor selects the circuits. Distinct
circuits do **not** guarantee disjoint relays, distinct guards or independent
network failures. WireGuard is never placed inside Tor.

The cryptographic primitives use maintained OpenSSL 3 EVP APIs
([HKDF](https://docs.openssl.org/3.0/man7/EVP_KDF-HKDF/),
[HMAC](https://docs.openssl.org/3.0/man7/EVP_MAC-HMAC/)); the custom wire protocol
is **not independently audited**. It provides no forward secrecy after pairing
PSK compromise, and cannot prevent traffic analysis, delay, loss, endpoint
compromise or admission denial of service. The fingerprint is a binding value,
not a replacement for a high-entropy pairing secret. Correctness tests and
successful calls do not constitute a cryptographic audit.

## One image, display-required installation

The reproducible image contains three physical partitions and the complete
offline installer:

- `BOOT`: 128 MiB FAT physical boot partition.
- `SYSTEM`: 512 MiB ext4 Alpine/Voider system, sealed read-only by installation.
- `STATE`: 256 MiB ext4 containing only the canonical integrity manifest and
  deterministic curated state archive; mounted read-only in operation.
- Runtime state is in RAM. Volatile CAP2/SFTP/Tor working data is not included in
  the external STATE fingerprint.

The raw image is exactly **940,572,672 bytes (897 MiB)** for nominal 1 GB cards
with at least that actual capacity. The first MiB holds the MBR/alignment gap;
BOOT, SYSTEM and STATE start at 1, 129 and 641 MiB and end at 129, 641 and
897 MiB respectively (exclusive ends). All starts are 1 MiB aligned. Larger
cards keep an intentionally unused tail; there is no automatic expansion.
`config/release-layout` records the exact byte geometry. The installer validates
sizes, starts, disk/partition identities, sector size and whole-card capacity.

The image boots directly from `root=UUID`. On an uninstalled boot its factory
OpenRC service:

1. obtains a private wired LAN address using DHCP, accepting no gateway, DNS or
   classless routes and disabling learned IPv6 routes;
2. generates a temporary Ed25519 SSH host key under `/run`;
3. starts SSH only if the flasher injected exactly one valid public key into the
   target card;
4. requires public-key authentication and disables passwords, keyboard-interactive
   authentication, forwarding, and unauthenticated fallback;
5. starts the offline factory UI and buttons when the mandatory supported display
   is detected; and
6. refuses installation when that display is absent.

No SSH key means management is off; it never means open SSH. An injected public
key enables restricted management initially and is carried into curated STATE
by installation. The same image is used for both display-equipped appliances.

### Guarded flash

Identify the whole-card target first:

```sh
lsblk -d -o NAME,SIZE,MODEL,SERIAL,TRAN,TYPE
```

To enable management SSH, select your own public key; its private half stays on
the administrator's computer. Replace `COMMIT` with the hash printed for the
validated image. `--readback` verifies all 940,572,672 raw bytes, including the
MBR, alignment gap and all three partitions, before optional key injection:

```sh
sudo ./scripts/flash-release-image.sh \
  release/voider-aarch64-COMMIT.img.gz /dev/EXACT_CARD \
  --ssh-key /path/to/management-key.pub --readback
```

To start with management off and no installed key, omit `--ssh-key`. The flasher verifies
the source checksum, exact decompressed length, MBR, v3 metadata and every
partition hash. It stages the verified raw source under `/var/tmp` (requires
897 MiB free; `TMPDIR` may select another disk filesystem). Raw `.img` sources
with matching metadata/checksum sidecars are also accepted. It rejects partition
targets, protected OS/source disks, active swap/mapped devices, undersized media,
invalid keys and weak RSA keys. After displaying model/serial/mounts it requires
the exact confirmation `FLASH /dev/EXACT_CARD`, safely unmounts that disk's
partitions, writes with `dd bs=4M iflag=fullblock oflag=direct conv=fsync`, syncs,
and performs the requested complete readback. It injects
the selected public key into the target BOOT partition after flashing; the
distributable source image is never modified and contains no developer key.

### Installation and management SSH

Attach the supported display and buttons, connect wired Ethernet, and complete
installation from the display. Installation validates and moves an injected
public key into curated STATE, removes its BOOT copy and factory entry point, and
generates unique SSH host keys. It never reboots automatically.

After the one explicit reboot, enabled `root` management is available by the
installed public key from private IPv4 addresses on the Ethernet uplink only.
Password, keyboard-interactive, public-WAN, phone-link, Voider-tunnel, Tor,
agent, X11, and TCP-forwarding access remain disabled. The key and on/off state
survive reboot; switching management off retains the key but closes new
management connections.

### Admin SSH keys

On the display, use `SYSTEM` → `MORE` → `SSH`. `ON` and `OFF` each require a held
confirmation; `OFF` retains the public key. `LOGIN KEY` asks to create a key or
replace it, explicitly warning that the old key will stop working. After that
held confirmation, insert a stick, check it, and hold `ERASE`. All existing
partitions are replaced. A new Ed25519 pair is generated only in private RAM,
written and verified on USB, then only the public half is installed. The private
RAM copy is deleted on success or failure. Success enables management and asks
you to record the new check code. Any USB failure leaves existing access intact.
`REMOVE` permanently revokes the login key and leaves management off.

SSH commands are `voider-main admin-ssh-enable`, `admin-ssh-disable`,
`admin-key-new`, and `admin-key-revoke`. Key creation requires an erase selection
from `voider-main usb-select erase`. The appliance cannot reconstruct a lost
administrator private key. Replacement requires a new erase confirmation.

### Display installation

The factory image loads the supported framebuffer/SPI and GPIO tooling before
installation. With the HAT physically attached, the four-button flow is:

`INSTALL VOIDER` → hold `INSTALL` → progress → `INSTALL COMPLETE` → `REBOOT`.

Failures show `INSTALL FAILED`, a concrete failing phase, `RETRY`, and safe
`POWER`. The UI invokes the same `voider-install` binary used by SSH and reads
its structured status; it does not duplicate installation logic. No HDMI,
keyboard, terminal, phone administration, or phone configuration is required.

After reboot, `voider-display` probes both HAT identity and a usable supported
framebuffer before starting. Both appliances require that physical interface;
there is no unattended or headless product path.

## Integrity model

### 1. Automatic internal SYSTEM verification

Installation hashes the complete raw BOOT partition and then the complete raw
SYSTEM partition. A domain-separated, versioned combined digest is derived in
that canonical order. The canonical manifest on STATE records those three
digests plus schema versions, partition order, labels, UUIDs, byte sizes, and
the common parent partition-table identity.

On every installed boot, BOOT and SYSTEM block devices are made read-only, the
layout is validated, and both raw partitions are hashed synchronously. No ready
marker, DHCP/network, SSH, Tor, or call service starts before a match. Any layout,
manifest, BOOT, SYSTEM, or combined mismatch fails closed, names the failing
phase, and leaves only safe power-off.

### 2. Human-owned external STATE fingerprint

The appliance calculates—not stores an expected copy of—a domain-separated
external fingerprint over:

- the complete canonical internal manifest, including BOOT/SYSTEM expectations;
- its integrity and layout schema versions and critical layout identity; and
- the SHA-256 of deterministic `state.tar.gz`.

Unused STATE space is never hashed. Runtime logs, public-IP discovery, CAP2
exchange data, SFTP mailboxes, Tor working data, and clean reboot activity do not
alter the fingerprint. Installation, pairing/import, language Save, removal, restore, and
factory reset show the new check code. The user
records it elsewhere; no on-device value can approve itself. After a successful
authorized change, **New check code → Write this down → I recorded it**
acknowledges the new external record and returns directly to the operation.
The code is recalculated before acknowledgement; a stale screen cannot approve
a different state. Subsequent boots retain **Matches / Differs** against that
separate record.

The normal display sequence is **Device check → Your check**. Device check
combines layout, manifest, BOOT, SYSTEM and combined verification without exposing
those internal pages. Your check shows the external code and retains Matches,
held Differs, the full digest and safe power-off. The internal digest pages remain
reachable through diagnostics. Approval is held in RAM for this boot only.

On installed boots, OpenRC keeps `voider-appliance` pending until both checks pass, then releases
networking, phone, time, SSH, Tor and call services in their existing order.
Distribution services also depend on this gate. An activation latch keeps existing
networking running during an authorized STATE update. New relationships have a
RAM admission marker until persistence succeeds; failed saves roll back the new
relationship. The STATE archive uses a same-filesystem rename and fsync; a failed
commit restores the previous archive and fingerprint publication.
First-time setup is a LAN-only exception: DHCP supplies a private address and
subnet, with no default gateway or Internet access. Optional management SSH and
local identity creation remain available. This restriction lasts until the
single reboot; normal networking then waits for both checks.

All physical views use the same 320×240 grid: title, status/decision area and four
fixed button cells. Double bars mark held actions. The palette is unchanged;
DINish Condensed SemiBold is embedded, with Bulgarian OpenType `locl` forms.
The minimum text size is 16 pixels; each component uses real raster metrics.
The font source is `playbeing/dinish`, commit
`a5f3b2a3b932336225815bf9005e3b72cc3de71c`; `scripts/build-ui-font.py`
reproduces the embedded atlas using Pillow/libraqm and fontTools.
Translations and glyphs for English, German and Bulgarian reside in SYSTEM and
RAM, never in STATE. The font's OFL notice ships in `/usr/share/voider`.

HOME displays connected/total clients and servers independently of the LINKS
cursor. LINKS retain role/slot order, identify every relationship, and show its
status and active method once. Share and Add remain available with populated
lists. The retained navigation covers connection copy/removal, network retry and
all seven path controls, SSH key/switch management, backup/restore/reset,
diagnostics, installation, confirmations, progress/results and power-off.

Settings → Language provides Next, Try and held Save. Try changes only RAM;
Save atomically commits `/etc/voider/node/language` through the same STATE-update
workflow as pairing, publishes the new code and requires acknowledgement.
A failed Save retains the previous persisted language and fingerprint. Factory
setup also permits language preview. Shutdown displays its transition, fills the
framebuffer with black and prevents the refresh loop from repainting it.

The compact SSH views show the same data:

```sh
voider-main status
voider-integrity stateprint
voider-ui --ssh --page integrity_state
```

## Normal operation

The [customer manual sources and build guide](docs/manual/README.md) produce
German, English and Bulgarian A5 PDFs (14 pages each; combined 43 pages) in
`release/`. They describe the USB workflow rewrite. Customer handoff remains
blocked on hardware/phone details, the absent display pairing-fingerprint check,
and the existing release gates; the manual
records these limits instead of inventing procedures.

The display remains a four-button, one-decision-per-screen interface. Links
owns pairing/import/removal; Settings owns language, backup/restore, SSH and
factory reset. Home provides Power, Check and Network. USB erasure always
requires a distinct held confirmation.
Backups contain the curated STATE archive and are bound to the combined SYSTEM
digest. Restore validates both before replacement and presents the resulting new
external fingerprint. After acknowledgement, explicitly restart to activate the
restored state; normal shutdown cannot overwrite it with stale runtime settings.

USB operations wait up to eight seconds for disk and partition readiness,
retain specific rejection reasons, and bind erase confirmation to the disk
insertion identity. External tools have time limits. A shared mount owner checks
unmount completion before reporting safe removal and recovers its own leftover
mount on the next attempt. Other mounted disks are rejected without detaching
them. Pairing bundle v1 and existing peer identities remain compatible.

USB media is mounted below `/run/voider`, which is writable runtime state. It
must never depend on creating a mountpoint on the sealed, read-only system
partition; the release checks enforce this boundary.

Imported-server internals keep the local connection slot `X` separate from the
certificate-assigned peer index `s`. Never derive s from X; transports and phone
address translation must retain the imported value.

The fixed phone link and ordinary diagnostics remain:

```sh
voider-main status
voider-selftest all
cat /run/voider/status
cat /run/voider/phone.status
```

## Shared implementation boundaries

Application helpers in `voider_util.hpp` own literal shell quoting, decoded
process exit codes, optional command echo, trimmed text capture, first-line and
whole-file reads, and 64-digit hex validation. `voider_config.hpp` owns the
first-matching-key parser used by configuration and USB metadata. Runtime status
parsers retain their distinct formats and duplicate-key rules. SFTP setup uses
one permission-setting text writer; `voider-tor-netns-socks` owns the shared
SOCKS interface setup for both OpenRC and WAN recovery.

STATE archive commits, atomic writes, bind-mount fallback, rollback and integrity
acknowledgement retain their existing owners. Boot firewall admission and service
supervision remain separate lifecycle steps. USB restore uses the shared STATE
transaction and prevents stale runtime state from overwriting the restored archive.

## Build and verification

Run host-safe tests without creating release artifacts or a preview:

```sh
./tests/run-release-tests.sh
```

This covers BOOT/SYSTEM corruption, manifest expectation changes, critical and
volatile STATE behavior, full/short fingerprint determinism, factory DHCP/SSH
policy, bootstrap removal, one-reboot ownership, mandatory-display gates,
management SSH switching, every page/button/press combination, isolated
button journeys through every page, UI checks in three languages,
font-metric geometry, stable role totals, atomic language/relationship saves,
failure rollback, and the two-check service gate. The isolated UI tests need
`bwrap` on the host running this suite. `make render-ui` generates translated views
and an inspectable gallery at `artifacts/ui-320x240/index.html`.
On an Alpine test host with dnsmasq, `sudo sh tests/factory-lan-netns.sh` checks
real DHCP leases/renewals, rejected gateway/classless routes, LAN reachability
and absent IPv4/IPv6 Internet routes in disposable network namespaces.

Earlier previews on both attached 320×240 panels passed 177 framebuffer
comparisons and an all-black check. Those results do not validate the rewritten
USB screens on hardware. Human readability remains pending. Language persistence
was tested by discarding RAM and reloading the archive; no hardware reboot occurred.

Build a versioned physical-test image only on the correct Alpine aarch64
builder. The rejected `candidate/` tree is not used:

```sh
make clean
make -j2
./tests/run-release-tests.sh
doas sh tests/usb-lifecycle.sh
doas unshare -m sh -c 'mount --make-rprivate /; exec sh tests/usb-loop-safety.sh'
doas sh tests/factory-lan-netns.sh
./scripts/stage-release-payload.sh release/voider-installer-payload-COMMIT.tar.gz
mkdir -p image-work
doas env TMPDIR="$PWD/image-work" VOIDER_BUILD_SKIP_MDEV=1 \
unshare -m sh -c 'mount --make-rprivate /; exec "$@"' sh \
  ./scripts/build-release-image.sh \
  release/voider-installer-payload-COMMIT.tar.gz \
  release/voider-aarch64-COMMIT.img.gz
gzip -t release/voider-aarch64-COMMIT.img.gz
(cd release && sha256sum -c voider-aarch64-COMMIT.img.gz.sha256)
doas unshare -m sh scripts/audit-release-image.sh \
  "$PWD/release/voider-aarch64-COMMIT.img.gz" "$PWD"
doas unshare -m sh tests/flash-loop-safety.sh \
  "$PWD/release/voider-aarch64-COMMIT.img.gz"
```

The builder refuses non-aarch64 hosts and physical-disk targets, uses a verified
loop-backed sparse image, records full-image and all-partition SHA256 digests
in v3 metadata, and checks the exact geometry. The complete audit checks partition tables and
filesystems, mounts every partition read-only (ext4 with no journal replay),
compares the full payload manifest and native binaries against the source build,
and rejects identity, credentials, private keys, logs, caches and harness files.
It also scans unallocated image bytes for encoded private keys. The separate
flasher test uses only a disposable loop image: confirmation refusal, safe
unmount, complete readback, temporary public-key injection and unused-tail preservation.

Build and audit both require at least 32 MiB available on BOOT, 128 MiB on
SYSTEM after allowing for a second installed payload copy plus 4 MiB of setup
slack, and 192 MiB on factory STATE. Reserved ext4 blocks are excluded from
available space. STATE contains only empty factory directories until installation;
normal curated archives use transactional replacement while working data stays
in RAM. A failed margin check stops the build without resizing or dropping packages.

The 2026-09-20 compact image passed the workstation and native aarch64 release
suites, complete image audit, and independent workstation size/MBR/hash checks.
The flasher passed a disposable-loop test of cancellation, safe unmount, all
897 MiB of readback, key injection, source preservation and an untouched tail.
Its raw SHA256 is
`5b50d59ef383f411340946ca5654fa532af3e24d448c4e47ff0e0aaf18a8fb2f`;
compressed SHA256 is
`d63dfd5a68040f2b00ac22bef175e756acc329157510ccb446e63b8e2c028acf`.
It retains the required package selection (154 installed packages) and all 24
release binaries, including the first-press USB detection fix. APK logging is
disabled during image construction so no installation log is created in SYSTEM.

| Factory filesystem | Used MiB | Available MiB | Free inodes |
| --- | ---: | ---: | ---: |
| BOOT | 40.39 | 85.63 | FAT: not applicable |
| SYSTEM | 147.79 | 303.59 | 28,574 |
| STATE | 0.15 | 234.44 | 51 |

Available space excludes filesystem overhead and reserved blocks. SYSTEM still
has 296.43 MiB after the 7.15 MiB installation allowance. Factory STATE has no
identity or archive yet; its archive/manifest-only model uses a small fixed set
of files. All byte and inode margin gates pass. Exact byte counts and logs are
in `release/verification-compact-20260920/`; metadata records source provenance.
The first candidate was rejected for APK's installation log and was rebuilt,
not published. No hardware was rebooted and no physical card was flashed.

Earlier reduction/call evidence remains in `release/voider-evidence-68881a782994.tar.gz`.
It includes user-confirmed calls and a 601-second Tor observation, not an hour.
Fresh physical installation of the compact image remains unrun; the publication
gates below still apply.

Before publishing, flash that exact candidate to both real appliance cards and pass:

- both appliances: fresh boot with supported displays, complete held-button
  installation, explicit reboot, internal match, and active display service;
- management variants: injected-key initial access and post-reboot access,
  password/no-key rejection, displayed ON/OFF state, OFF/ON across reboot, and
  key create/replace/revoke behavior; and
- both: labels/order/UUIDs/sizes/common parent, BOOT and SYSTEM read-only, STATE
  read-only, runtime in RAM, identical fingerprint presentation, and no service
  readiness before internal match.

Only after those checks pass may that exact versioned image be declared the
release and the UI preview generated with:

```sh
make render-ui
# Open artifacts/ui-320x240/index.html; text bounds accompany every frame.
```

Direct public WireGuard and hole punching remain implemented but are not claimed
as proven unless exercised from separate public networks.

AMDCC.
