# Next Weekend: peerd False Negative and Simplification Review

Use this note as the handoff for the next Voider session focused on the HP4
stress run, `peerd` recovery, and architecture simplification.

## Starting Point

- Read `AGENTS.md` first.
- The two live Voider appliances were forced to `PATHS_AVAILABLE=hp4`.
- The stale generated import/export inventory mismatch was fixed by removing
  only the dangling `client_80` from `voider-941c52b9`.
- Both boxes now report `CONNECTIONS 157`.
- The remaining issue is not import/export inventory. It is a `peerd` status
  false negative.

## Observed Error

`voider-1484fd02` reports all saved connections up:

```text
CONNECTIONS 157
total_connected=157
holepunch_ipv4=157
```

`voider-941c52b9` reports five saved connections down even though HP4 is the
only allowed transport:

```text
CONNECTIONS 157
total_connected=152
holepunch_ipv4=152
client_12_state=connecting
client_13_state=connecting
client_18_state=connecting
client_25_state=connecting
client_74_state=connecting
```

Manual tunnel pings from `voider-941c52b9` over `wg0` succeeded for those five
slots:

```text
12 ok
13 ok
18 ok
25 ok
74 ok
```

That means the WireGuard/HP4 data path works, but `peerd` did not promote those
peers to connected. This is a real bug: the status/UI layer is reporting a
usable tunnel as down.

## Likely Failure Mode

The state machine can split asymmetrically:

1. CAP2 coordinates a remote connection.
2. HP4 punching and WireGuard handshake succeed.
3. One side promotes to `holepunch4`.
4. The other side misses its proof/promotion window, then returns to CAP2 wait
   or backoff.
5. The kernel WireGuard peer may still have a valid endpoint, handshake, and
   pingable tunnel, but `peerd` remains in `connecting` or `offline`.

The false negative is therefore between the kernel WireGuard state and the
`peerd` state machine, not in HP4 packet reachability itself.

## Important Separation

Do not mix this with the already-fixed inventory mismatch.

- Inventory mismatch was a stale import/export fixture problem.
- The current bug is a `peerd` proof/recovery problem.
- Slot numbers alone are not identity. Compare role plus slot and, for
  import/export integrity, compare `USB_FP`.

## Suggested Fix Direction

Avoid an HP4-only pile of special cases if possible. Prefer one shared helper
for all WireGuard-backed transports:

```cpp
static bool wireguard_proven_alive(Peer& peer, Method method) {
    return method != Method::Tor &&
           available(method) &&
           wireguard_endpoint_family(peer) == method_family(method) &&
           handshake(peer) > 0 &&
           wireguard_ping(peer);
}
```

Use it in two places:

1. Normal proof/promotion, replacing duplicated handshake and endpoint-family
   checks.
2. Recovery from CAP2 wait/backoff when a known WireGuard peer is already alive.

Keep Tor separate. It does not use the same proof.

This should reduce code rather than add transport-specific branches. The user
believes the core architecture can be simplified further while losing lines of
code; treat that as an explicit design goal for this pass.

## Safety Requirements

Do not promote a peer merely because an endpoint exists. Promotion must require:

- the expected peer key,
- the expected configured relationship,
- an allowed WireGuard-backed method,
- matching endpoint family,
- a nonzero/recent handshake,
- successful tunnel ping.

For the first implementation, it is acceptable to validate the recovery through
HP4 because that is the observed failure. However, the code shape should be
transport-agnostic for WireGuard methods so direct4/direct6/hp6/LAN do not grow
separate proof logic later.

## Tests To Add

Add or extend a `peerd-health` style test for:

- kernel/WireGuard peer already alive,
- `peerd` stuck waiting for CAP2 or in retry/backoff,
- `wireguard_proven_alive` succeeds,
- `peerd` promotes the peer instead of reporting a false negative.

Also keep an import/export inventory regression:

- every exported client `USB_FP` on one appliance has exactly one imported
  server `USB_FP` on the other appliance,
- no extra generated client remains without a matching imported counterpart,
- role plus slot remains distinct from slot alone.

## Suggested Model and Reasoning Level

Use the strongest available coding model with high reasoning. This is a
state-machine simplification task, not a small syntax patch.

The model should reason through:

- `Phase::Remote`,
- `Phase::RemoteJob`,
- `Phase::Choose`,
- `Phase::HoleJob`,
- `Phase::Proof`,
- `Phase::Up`,
- `Phase::Backoff`,
- reset/reconcile behavior,
- and the boundary between CAP2 proof and kernel WireGuard reality.

Do not optimize for a quick HP4-only patch if a smaller shared proof abstraction
removes duplicated logic and makes the state machine easier to audit.
