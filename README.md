![Voider architecture: isolated phone paths, connection selection, boot integrity and USB pairing](docs/diagrams/voider-overview.png)

Voider lets Ethernet phones on separate networks call each other by IP address
as if they were on the same LAN.

[Diagram source (SVG)](docs/diagrams/voider-overview.svg)

<details>
<summary>Network and integrity details</summary>

- **Servers we import.** We choose import slot `X` (2–254). The server assigns us
  certificate slot `s` (2–254). Different servers can assign the same `s` because
  each import has its own `netnsX`.

  | Path | Importing box · inside `netnsX` |
  | --- | --- |
  | WireGuard | `wgX` at `172.31.0.s/24` (first `172.31.0.2`, last `172.31.0.254`) |
  | Tor | `tdsX` at `172.27.s.2/30` (first `172.27.2.2`, last `172.27.254.2`) |

- **Clients we serve.** We assign each client its `s`. Clients share `wg0` for
  WireGuard. Each client using Tor gets its own interface, giving **253 possible
  Tor interfaces** from `tcs2` through `tcs254`.

  | Path | Serving box · default namespace |
  | --- | --- |
  | WireGuard | Shared `wg0` at `172.31.0.1/24` |
  | Tor | `tcs` for slot `s` at `172.27.s.1/30` (first `172.27.2.1`, last `172.27.254.1`) |

- **Routing.** `X` selects the local namespace. Slot `s` identifies the client.
  Calls use the same addresses over WireGuard and Tor.

  | Purpose | One end | Other end |
  | --- | --- | --- |
  | Bridge link inside one box | `brX` in the default namespace · `172.30.X.1/30` | `vethXb` in `netnsX` · `172.30.X.2/30` |
  | Call between boxes | Server · `172.29.1.1` | Client in slot `s` · `172.29.s.1` |

- **Phone link.** The two blue arrows are dial targets on one cable. The appliance
  (`172.16.19.86/30` on `eth1`) pings the factory-reset phone at `172.16.19.85`.
- **Tor fallback.** Imported-server namespaces reach Tor at `172.30.255.1:19050`
  (SOCKS). Tor encrypts. Tundup authenticates with the paired secret and USB
  fingerprint, sends each voice packet on both streams and forwards the first valid copy.
- **CAP2 mailboxes:** each role and slot has a separate account, key path and
  chroot. Incoming CAP2 uses client accounts; server accounts have no authorized
  key. From the peer, OFFER and READY go to `/in`; ANSWER is read from `/out`.
  Records use pair-secret HMAC, a shared transaction ID and atomic RAM storage.
  Each mailbox retains one pending exchange; records are capped at 1 KiB
  including the newline. Active inboxes have four file entries and a
  four-page tmpfs ceiling (16 KiB on the release kernel). Restricted SFTP
  sessions enforce the same file limit, 32 descriptors and four processes.
  Fresh mailbox accounts accept public keys without a password-change
  prompt; passwords remain disabled. Junk, expired exchanges, interrupted
  uploads and orphan answers are cleaned automatically.

  | Role | Account | Mailbox root |
  | --- | --- | --- |
  | Client | `vmcNNN` | `/var/sftp/clients/vmbNNN` |
  | Server | `vmsNNN` | `/var/sftp/servers/vmbNNN` |

- **Runtime logs:** logs live in RAM. Every ten seconds, the connection
  coordinator trims logs above 256 KiB to approximately the newest 64 KiB
  while preserving the open file inode. Reboot clears these logs.

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

### Phones

Start with a factory-reset phone and plug it into the appliance’s phone Ethernet port.

- **Grandstream GXP1610** — tested with Voider.
- **Yealink SIP-T53** — exchanged direct IP calls with a GXP1610 on an ordinary
  LAN. The SIP-T53 has yet to be tested through Voider. Its SIP port during the
  LAN test and its factory-default SIP port are both unconfirmed.

Voider expects the phone to use SIP port `5060`. The appliance UI currently
offers no setting to change that port.

## Build and flash

Use a Raspberry Pi running **64-bit Alpine Linux 3.24** with Internet access.
Allow about **4 GB of free space** on the drive holding the clone. These commands assume
an account with `doas` administrator access. Run each block in order; stop if a
command fails. Build on this Pi, then flash a separate microSD card in a USB reader.

Install the tools needed to download the source:

```sh
doas apk add git python3
```

Download the source:

```sh
git clone https://github.com/slave-blocker/voider_ai.git
cd voider_ai
```

Fetch and verify the locked packages, install the exact build tools, then build:

```sh
doas ./scripts/prepare-build.sh
make clean
make -j2
doas ./scripts/stage-release-payload.sh
```

`config/build-dependencies.json` fixes the build and image package versions,
archive checksums and release timestamp. Keep `image-work/packages/` for future
offline builds: Alpine may eventually remove old archives. An absent or changed
package stops the build; it never silently substitutes a newer version.
This fixes the inputs; byte-identical filesystem images are not promised.

Create the image from the verified local cache, without network downloads:

```sh
doas ./scripts/build-release-image.sh
```

Everything stays inside this clone: programs in `build/`, temporary build and
flash files in `image-work/`, and the finished image in `release/`. Temporary
working folders are removed when the scripts exit normally. No `TMPDIR` setting
is needed. The build produces these three files together:

```text
release/voider-aarch64.img.gz
release/voider-aarch64.img.gz.meta
release/voider-aarch64.img.gz.sha256
```

Insert the target microSD card into a USB reader connected to the build Pi.
Identify it by its size and model:

```sh
lsblk -o NAME,SIZE,MODEL,TRAN,MOUNTPOINTS
```

Do not select the disk running the build Pi. Enter the **whole USB card device**,
for example `/dev/sda`, not a partition such as `/dev/sda1`:

```sh
printf 'USB card device: '
read -r CARD
doas ./scripts/flash-release-image.sh release/voider-aarch64.img.gz "$CARD" --readback
```

The flasher validates the source and target, shows the selected disk, and asks
you to type `FLASH /dev/...` before erasing it. Wait for **Flash complete**.
The card must hold at least 940,572,672 bytes (nominal 1 GB or larger).

Management SSH is off by default. To enable it, append
`--ssh-key /path/to/your-public-key.pub` to the flashing command. Supply only a
public key; keep its private key on your management computer.

Put the flashed card in the Voider, connect its supported display and buttons,
Ethernet uplink and supported factory-reset phone, then power it on. Hold
**INSTALL** on the display and follow the instructions. Installation is offline
and requests one reboot. Repeat for the second appliance, then follow the
[manual](docs/manual/voider-manual-de-en-bg.pdf) to pair them and make a call.

## Monero

![xmr](xmr.gif)

*Long live the discrete log problem of H.*

## Contact

Please do contact me for critiques, suggestions, questions, kudos, and even mobbing attempts are welcome.

Remember, if your hardware is backdoored anyway, backdoored you are...

<details>
<summary>Which proprietary firmware does Voider use?</summary>

We checked two appliances running Alpine 3.24.4. The table lists the vendor
firmware we identified from their boot configuration and live controller diagnostics.

| Component | Raspberry Pi 4 Model B (rev. 1.4) | Raspberry Pi 3 Model B (rev. 1.2) |
| --- | --- | --- |
| Bootloader | The onboard EEPROM starts the board. | The board loads `bootcode.bin` from the microSD card. |
| VideoCore | `start4.elf` on the card continues the boot process. | `start.elf` on the card continues the boot process. |
| Wi-Fi | The BCM4345/6 radio loads firmware from the card. | The BCM43430/1 radio loads firmware from the card. |
| Bluetooth | The controller reported firmware revision 382. | The controller reported firmware revision 508. |
| USB 3 | The VIA VL805 controller reported firmware version `000138a1`. | This board has no VL805 controller. |

Both Wi-Fi interfaces were down when checked. Each card also held firmware for
other chip models. The Bluetooth revisions confirm the controllers initialized;
the exact Bluetooth patch files loaded from the card could not be verified.

We identified source code for every running Linux application we observed on
both appliances, including Voider's call software. The check did not cover
firmware inside the phone, microSD controller or external USB Ethernet adapter.
Finding proprietary firmware does not establish that a device has a backdoor.

[Raspberry Pi boot files](https://www.raspberrypi.com/documentation/computers/configuration.html#boot-folder-contents) · [Raspberry Pi firmware licence](https://github.com/raspberrypi/firmware/blob/master/boot/LICENCE.broadcom) · [Broadcom Wi-Fi driver and firmware](https://wireless.docs.kernel.org/en/latest/en/users/drivers/brcm80211.html)

</details>

@ IRC: **monero-pt**

Special thanks to Andreas Hein!

A donation is the best nation!
