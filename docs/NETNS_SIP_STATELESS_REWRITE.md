# Imported-server SIP rewrite

Imported-server SIP is stateless inside `netnsX`. It uses raw-table NOTRACK and
NFQUEUE, not conntrack NAT. RTP/SRTP and other non-SIP UDP remain in the kernel
forwarding/NAT path.

`X` selects the local namespace, handoff address `10.X.1.1`, and `tdsX`. The
imported bundle supplies server index `s`, which selects `172.29.s.1`. Never
derive `s` from `X`.

## Phone to remote server

The packet enters `netnsX` as:

```text
172.16.19.85 -> 10.X.1.1
```

NFQUEUE rewrites headers and SIP body to:

```text
172.29.s.1 -> 172.29.1.1
```

The namespace routes it through `wgX` for WireGuard or `tdsX` for Tor.

## Remote server to phone

The packet enters `netnsX` as:

```text
172.29.1.1 -> 172.29.s.1
```

NFQUEUE changes the IPv4 destination to `172.16.19.85` and the source to the
per-boot phone-visible fake server address. SIP caller/source occurrences are
normalized to that fake address, but Request-URI and To retain the logical
called identity `172.29.s.1`.

Payload-length changes rebuild Content-Length, IPv4 total length, UDP length,
and both checksums before the packet is accepted.

## Media

Non-SIP return UDP arriving on `wgX` or `tdsX` is DNATed to bridge address
`172.30.X.1`. The default namespace explicitly maps the resulting
`10.X.1.1 -> 172.30.X.1` packet to the phone and the per-boot fake peer address.
This seeds equivalent conntrack state from either media direction, so an
answering phone may wait for inbound RTP without deadlocking the call. The
phone still sees SIP and media from the same peer identity.
