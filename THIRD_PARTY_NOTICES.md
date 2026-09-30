# Third-Party Notices

Voider is built on system packages, libraries, tools, hardware, and assets that
are not owned by the Voider creator. Their licenses, notices, product terms, and
trademark rules must be preserved when building or shipping source, binaries,
images, devices, or services.

Known items to verify before any public binary or device shipment:

- Alpine Linux packages and Linux kernel: per-package licenses and corresponding
  source obligations.
- libnetfilter_queue / netfilter components: GPL-related obligations may apply,
  especially to `voider-nfqd`.
- OpenSSL / libcrypto: preserve applicable notices and license terms.
- Tor, OpenSSH, WireGuard tools, BusyBox, iptables/nftables-related packages,
  chrony, curl/wget, and other image packages: preserve per-package licenses.
- DINish font: SIL Open Font License, included at `assets/fonts/OFL.txt`.
- Adafruit PiTFT Plus 320x240 2.8" TFT + Resistive Touchscreen, Product ID 2298:
  use genuine purchased modules unless you have separately verified and complied
  with any hardware design, documentation, trademark, and reseller terms.
- Raspberry Pi hardware, boot firmware, names, and marks: follow the applicable
  vendor terms and do not imply certification, sponsorship, or endorsement.

The commercial Voider terms do not override third-party licenses. If a third-party
license grants rights or requires source/notices/install information, comply with
that license for that component.

Third-party names are used only to identify compatibility or dependencies.
Voider is not affiliated with, endorsed by, certified by, or sponsored by those
third-party vendors or projects.
