# Voider

![Voider architecture: isolated phone paths, connection selection, boot integrity and USB pairing](docs/diagrams/voider-overview.png)

[Diagram source (SVG)](docs/diagrams/voider-overview.svg)

<details>
<summary>Network and integrity details</summary>

- **Indexes and routing:** `X` is the local imported-server slot; `s` comes from
  the paired certificate/WireGuard address. They are independent. Each `netnsX`
  contains `wgX = 172.31.0.s`, `vethXb`, and NFQUEUE `1000 + X`. The `.2` bridge
  endpoint is inside `netnsX`; `.1` is in the default namespace. WireGuard UDP
  sockets remain in the default namespace. SIP uses NOTRACK and stateless rewrite.
- **Phone link:** the factory-reset phone uses `172.16.19.85`, with the appliance
  gateway at `172.16.19.86/30` on `eth1`. Readiness is a ping; phone web
  administration is not required. The two blue arrows show dial targets over
  this one physical link. Clients of this appliance share `wg0`.
- **Tor fallback:** `tcs+` serves paired clients and `tds+` serves imported servers;
  the namespace SOCKS helper is `172.30.255.1`. Tor supplies encryption, and
  tundup authenticates using the paired secret and USB fingerprint. Its two
  bidirectional streams deliver the first valid copy.
- **CAP2 mailboxes:** each role and slot has a separate account, key path and
  chroot. Incoming CAP2 uses client accounts; server accounts have no authorized
  key. From the peer, OFFER and READY go to `/in`; ANSWER is read from `/out`.
  Records use pair-secret HMAC, a shared transaction ID, atomic RAM storage,
  and size, count and lifetime limits.

  | Role | Account | Mailbox root |
  | --- | --- | --- |
  | Client | `vmcNNN` | `/var/sftp/clients/vmbNNN` |
  | Server | `vmsNNN` | `/var/sftp/servers/vmbNNN` |

- **Integrity:** the device checks the complete raw BOOT and SYSTEM partitions.
  The human STATE check covers the internal manifest and deterministic saved
  STATE archive. Compare the displayed fingerprint with your trusted record;
  Internet and calls stay off until both checks pass. After an intentional
  STATE change, record the new check code.

</details>

Manual: [German / English / Bulgarian](docs/manual/voider-manual-de-en-bg.pdf)

Voider is a source-available appliance project for private phone-to-phone calling
through small, reproducible Raspberry Pi devices and supported Ethernet phones.

Voider is not FOSS. The source is public so individuals can download it, study it,
modify it, build it, and use it privately for personal and noncommercial purposes.

## License

Personal and noncommercial use is allowed under the terms in [LICENSE](LICENSE).

Commercial use is not granted by downloading this repository. If you want to
manufacture, sell, bundle, host, market, support, certify, brand, or distribute
Voider devices, Voider services, or commercial Voider builds, you need a signed
commercial agreement with the creator.

Companies should use the commercial licensing pack:

[docs/legal/voider-commercial-licensing-pack.pdf](docs/legal/voider-commercial-licensing-pack.pdf)

Contact for commercial licensing: dollner@gmx.de

Got complaints? Please direct them to `/dev/null`.

## Legal Boundary

The custom Voider license applies only to creator-owned Voider materials. Third-party
software, libraries, fonts, operating-system packages, hardware, hardware designs,
product names, and trademarks keep their own licenses and owners. If a third-party
license gives you rights or imposes obligations, that third-party license controls
for that component.

Do not remove copyright notices, license notices, or source-offer obligations from
third-party components. In particular, GPL-covered parts must be handled under GPL
terms where the GPL applies.

Voider is not affiliated with, endorsed by, certified by, or sponsored by Adafruit,
Raspberry Pi, Alpine Linux, Tor, OpenSSH, OpenSSL, WireGuard, or any other
third-party project or vendor named here.

## Hardware

The intended display is the **Adafruit PiTFT 2.2" HAT Mini Kit —
320x240 2.2" TFT, Product ID 2315**, with four physical buttons and no touch
input. Voider is operated using the four buttons.

Use a genuine purchased display module. If you sell devices, respect Adafruit's
product, trademark, reseller, and documentation terms. Do not imply Adafruit
approval or certification.

Voider requires a supported physical display and buttons. Headless installation
is not supported. The installer refuses to continue if the supported display is
not detected.

Use a Raspberry Pi with 64-bit/aarch64 boot support and a 2x20 GPIO header for
the display. The release image uses Alpine's Raspberry Pi kernel and bootloader,
64-bit boot mode.

## Build

The repository contains the source and release tooling used to build Voider binaries
and stage a flashable release image.

Native binaries:

```sh
make
```

Stage the offline installer payload after a native build:

```sh
./scripts/stage-release-payload.sh release/voider-installer-payload.tar.gz
```

Build the fixed-size flashable image on an Alpine aarch64 builder as root. The
build creates the compressed image, metadata, and checksum files together:

```sh
./scripts/build-release-image.sh \
  release/voider-installer-payload.tar.gz \
  release/voider-aarch64.img.gz
```

The expected outputs are:

```text
release/voider-aarch64.img.gz
release/voider-aarch64.img.gz.meta
release/voider-aarch64.img.gz.sha256
```

Flash with explicit source and target validation:

```sh
./scripts/flash-release-image.sh release/voider-aarch64.img.gz /dev/EXACT_CARD
```

## Monero

![xmr](xmr.gif)

*Long live the discrete log problem of H.*

## Contact

Please do contact me for critiques, suggestions, questions, kudos, and even mobbing attempts are welcome.

Remember, if your hardware is backdoored anyway, backdoored you are...

@ IRC: **monero-pt**

Special thanks to Andreas Hein!

A donation is the best nation!
