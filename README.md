# vpp-fib-ipfix

A [VPP](https://fd.io/) plugin that exports FIB programming events over IPFIX
(RFC 7011): every time a FIB entry's forwarding is installed, changed or
removed, a record goes to the IPFIX collector. Several changes to one entry
while its record is still in the packet being filled collapse into that one
record, carrying the latest state and a count of the changes.

Status: experimental. Built and tested against VPP master `edae1a0f6`
(v26.10-rc0-556, 2026-09-23) on Ubuntu 24.04 arm64, debug build. The plugin's 9 tests
pass (9). With the core patch applied, VPP's own test_fib, test_ip4, test_ip6, test_mpls, test_flowprobe and test_ipfix_export pass: 150 run, 144 passed, 6 skipped (non-extended run), plugin loaded but not enabled.

## What is here

| path | what |
|---|---|
| `patches/0001-fib-add-install-notify-...patch` | small core patch (+75 lines): a notifier in `fib_entry_src.c` |
| `src/plugins/fibipfix/` | the plugin |
| `test/test_fibipfix.py` | tests for VPP's `make test` framework |
| `apply.sh` | applies the patch and copies the plugin and test into a VPP tree |

## Why a core patch

VPP has no callback for "this FIB entry's forwarding was just programmed".
The patch adds one at the single place where that happens:
`fib_entry_src_action_install()` / `fib_entry_src_action_uninstall()`.
Every entry owns one load-balance object; install creates it and puts it in
the forwarding trie (ADD) or modifies it in place (UPDATE), and uninstall
takes it out (REMOVE). Activate and reactivate both go through install, so
changes that do not come from an API call are caught too: an adjacency
resolving, a recursive next hop moving.

```c
void fib_entry_install_notify_register (fib_entry_install_notify_fn_t fn);
void fib_entry_install_notify_unregister (fib_entry_install_notify_fn_t fn);
/* fn (fib_node_index_t fib_entry_index, fib_entry_install_event_t event) */
```

Callbacks run on the main thread with the workers at the barrier, right after
the change; the entry is still valid during REMOVE.

Note: install runs on every reactivation, so an UPDATE can arrive when
nothing visible changed. The coalescing below absorbs that.

## How the plugin works

- **Coalescing window = the open packet.** Each event is written into the
  open IPFIX packet (one per address family) at once, with the entry's state
  at that moment. If the entry already has a record in that open packet, the
  record is overwritten in place and its change count goes up. ADD+UPDATE
  stays ADD (the collector has not seen it yet); ADD+REMOVE takes the record
  out of the packet (the last record moves into its slot). Once the packet is
  sent, the next event for the entry starts a new record in the next packet.
- **Sending.** The open packet goes out when the next record would not fit
  (exporter path MTU, or 255 records), and every `interval` (default 100 ms),
  through exporter 0 (`set ipfix exporter ...`). One template per address
  family.
- **Resync.** IPFIX over UDP can lose packets; `fib ipfix resync` queues every
  programmed IPv4/IPv6 entry (event 4).

### Record

| field | IE | size |
|---|---|---|
| table id | ingressVRFID (234) | 4 |
| prefix | destinationIPv4Address (12) / destinationIPv6Address (28) | 4 / 16 |
| prefix length | destinationIPv4PrefixLength (13) / destinationIPv6PrefixLength (30) | 1 |
| next hop of the first path | ipNextHopIPv4Address (15) / ipNextHopIPv6Address (62) | 4 / 16 |
| resolving interface (`~0` if none) | egressInterface (14) | 4 |
| time of the last change folded in | observationTimeMilliseconds (323) | 8 |
| event: 1 add, 2 update, 3 remove, 4 resync | enterprise IE 1 | 1 |
| number of changes folded into this record | enterprise IE 2 | 4 |
| number of paths | enterprise IE 3 | 2 |

The enterprise number defaults to 32473 (RFC 5612, reserved for
documentation); set your own with `enterprise <pen>`.

## CLI

```
set ipfix exporter collector 192.0.2.10 src 192.0.2.1 template-interval 20
fib ipfix enable [interval <ms>] [enterprise <pen>] [domain <id>] [src-port <port>]
fib ipfix enable disable
fib ipfix flush
fib ipfix resync
show fib ipfix
```

## Building

```
git clone https://gerrit.fd.io/r/vpp && cd vpp
/path/to/vpp-fib-ipfix/apply.sh .
make build          # or make build-release
make test-debug TEST=test_fibipfix
```

## Testing

`test/test_fibipfix.py` decodes the IPFIX bytes itself (enterprise fields
included) and checks: templates, ADD with next hop and interface, coalescing
of three changes into one record with the final state, ADD+REMOVE sending
nothing, a change after the packet was sent giving a new record (while a
route still in the open packet stays one record), REMOVE, IPv6 in a
non-default table, resync, and that IPFIX sequence numbers count data records
across packets with no prefix twice in one packet.

Seen in that last test: adding 100 routes via the same next hop gives 100 ADD
and 42 UPDATE records. The UPDATEs come when the shared path-list reaches 64
children (`FIB_PATH_LIST_POPULAR` in fib_path_list.c) and VPP re-stacks every
child's forwarding; the routes whose ADD had already been sent get a new
record. That is real re-programming, reported as the design intends.

## Limits / ideas

- One path per record (first path + path count). Per-path records or a
  subTemplateList (RFC 6313) would carry all of them.
- MPLS entries are skipped (counted in `show fib ipfix`).
- Not checked yet: whether a change of best source shows up as UPDATE or as REMOVE then ADD.
- No binary API yet, CLI only.

## License

Apache-2.0, like VPP. The core patch is written to be offered upstream.
