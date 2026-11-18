#!/usr/bin/env python3
"""fibipfix plugin tests: FIB entry programming events exported over IPFIX"""

import struct
import time
import unittest
from ipaddress import ip_address, ip_network

from framework import VppTestCase
from asfframework import VppTestRunner
from config import config
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_pg_interface import CaptureTimeoutError
from scapy.layers.inet import UDP

EV_ADD, EV_UPDATE, EV_REMOVE, EV_RESYNC = 1, 2, 3, 4
PEN = 32473

# IANA IEs
IE_VRF = 234
IE_DST4, IE_LEN4, IE_NH4 = 12, 13, 15
IE_DST6, IE_LEN6, IE_NH6 = 28, 30, 62
IE_EGRESS = 14
IE_TIME_MS = 323
# enterprise IEs (PEN 32473)
E_EVENT, E_COUNT, E_PATHS = 1, 2, 3


class IpfixMessage:
    """Minimal IPFIX (RFC 7011) decoder that keeps the raw template layout,
    so the test checks the bytes the plugin writes, enterprise bits included"""

    def __init__(self, payload, templates):
        ver, length, self.export_time, self.seq, self.domain = struct.unpack(
            "!HHIII", payload[:16]
        )
        assert ver == 10, ver
        assert length == len(payload), (length, len(payload))
        self.templates = []  # template ids defined in this message
        self.records = []  # (template_id, {(pen, ie): bytes})
        off = 16
        while off < length:
            set_id, set_len = struct.unpack("!HH", payload[off : off + 4])
            body = payload[off + 4 : off + set_len]
            if set_id == 2:
                self._parse_template_set(body, templates)
            elif set_id >= 256 and set_id in templates:
                self._parse_data_set(set_id, body, templates[set_id])
            off += set_len

    def _parse_template_set(self, body, templates):
        off = 0
        while off + 4 <= len(body):
            tid, count = struct.unpack("!HH", body[off : off + 4])
            off += 4
            fields = []
            for _ in range(count):
                ie, flen = struct.unpack("!HH", body[off : off + 4])
                off += 4
                pen = 0
                if ie & 0x8000:
                    (pen,) = struct.unpack("!I", body[off : off + 4])
                    off += 4
                    ie &= 0x7FFF
                fields.append((pen, ie, flen))
            templates[tid] = fields
            self.templates.append(tid)

    def _parse_data_set(self, tid, body, fields):
        rec_len = sum(f[2] for f in fields)
        off = 0
        while off + rec_len <= len(body):
            rec = {}
            for pen, ie, flen in fields:
                rec[(pen, ie)] = body[off : off + flen]
                off += flen
            self.records.append((tid, rec))


def u(b):
    return int.from_bytes(b, "big")


def decode_record(rec):
    """Turn a raw record into a dict with readable values"""
    if (0, IE_DST4) in rec:
        dst = ip_address(rec[(0, IE_DST4)])
        plen = u(rec[(0, IE_LEN4)])
        nh = ip_address(rec[(0, IE_NH4)])
    else:
        dst = ip_address(rec[(0, IE_DST6)])
        plen = u(rec[(0, IE_LEN6)])
        nh = ip_address(rec[(0, IE_NH6)])
    return {
        "prefix": ip_network("%s/%d" % (dst, plen)),
        "table_id": u(rec[(0, IE_VRF)]),
        "nh": nh,
        "egress": u(rec[(0, IE_EGRESS)]),
        "time_ms": u(rec[(0, IE_TIME_MS)]),
        "event": u(rec[(PEN, E_EVENT)]),
        "count": u(rec[(PEN, E_COUNT)]),
        "paths": u(rec[(PEN, E_PATHS)]),
    }


@unittest.skipIf("fibipfix" in config.excluded_plugins, "Exclude fibipfix tests")
class TestFibIpfix(VppTestCase):
    """fibipfix: FIB programming events over IPFIX"""

    @classmethod
    def setUpClass(cls):
        super(TestFibIpfix, cls).setUpClass()
        cls.create_pg_interfaces(range(3))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()
            i.disable_ipv6_ra()
        # pg0 is the collector
        cls.vapi.set_ipfix_exporter(
            collector_address=cls.pg0.remote_ip4,
            src_address=cls.pg0.local_ip4,
            path_mtu=1450,
            template_interval=1,
        )

    @classmethod
    def tearDownClass(cls):
        cls.vapi.cli("set ipfix exporter collector 0.0.0.0")
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super(TestFibIpfix, cls).tearDownClass()

    def setUp(self):
        super(TestFibIpfix, self).setUp()
        # a long interval: the tests flush by hand
        self.vapi.cli("fib ipfix enable interval 1000000 threshold 1000000")
        self.templates = {}

    def tearDown(self):
        self.vapi.cli("fib ipfix enable disable")
        super(TestFibIpfix, self).tearDown()

    def collect(self, timeout=3):
        """Flush and return (records, messages) seen on the collector.

        Templates arrive every second (template_interval 1), so stop on an
        absolute deadline, not on a quiet gap: the capture is never quiet.
        """
        self.pg_enable_capture([self.pg0])
        self.pg_start()
        self.vapi.cli("fib ipfix flush")
        messages = []
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                p = self.pg0.wait_for_packet(remaining)
            except CaptureTimeoutError:
                break
            if UDP not in p or p[UDP].dport != 4739:
                continue
            m = IpfixMessage(bytes(p[UDP].payload), self.templates)
            messages.append(m)
            if m.records:
                # the flush sends everything at once: settle briefly, then stop
                deadline = min(deadline, time.time() + 1.0)
        records = [decode_record(r) for m in messages for (_, r) in m.records]
        return records, messages

    def wait_templates(self):
        """Templates come from the exporter process (template_interval 1 s)"""
        for _ in range(5):
            self.collect(timeout=2)
            if len(self.templates) >= 2:
                return
        self.fail("no fibipfix templates seen: %s" % self.templates)

    def for_prefix(self, records, prefix):
        return [r for r in records if r["prefix"] == ip_network(prefix)]

    def test_templates(self):
        """Templates carry the enterprise IEs with PEN 32473"""
        self.wait_templates()
        for tid, fields in self.templates.items():
            ies = [(pen, ie) for pen, ie, _ in fields]
            self.assertIn((PEN, E_EVENT), ies)
            self.assertIn((PEN, E_COUNT), ies)
            self.assertIn((PEN, E_PATHS), ies)
            self.assertIn((0, IE_VRF), ies)

    def test_add(self):
        """A new route is exported once as ADD with its next hop"""
        self.wait_templates()
        route = VppIpRoute(
            self, "10.10.0.0", 16, [VppRoutePath(self.pg1.remote_ip4, 0xFFFFFFFF)]
        )
        route.add_vpp_config()
        records, _ = self.collect()
        mine = self.for_prefix(records, "10.10.0.0/16")
        self.assertEqual(len(mine), 1, records)
        r = mine[0]
        self.assertEqual(r["event"], EV_ADD)
        self.assertEqual(r["table_id"], 0)
        self.assertEqual(r["nh"], ip_address(self.pg1.remote_ip4))
        self.assertEqual(r["egress"], self.pg1.sw_if_index)
        self.assertEqual(r["paths"], 1)
        self.assertGreaterEqual(r["count"], 1)
        route.remove_vpp_config()

    def test_coalesce(self):
        """Several updates before a flush give one record with the last state"""
        self.wait_templates()
        route = VppIpRoute(
            self, "10.20.0.0", 16, [VppRoutePath(self.pg1.remote_ip4, 0xFFFFFFFF)]
        )
        route.add_vpp_config()
        route.modify([VppRoutePath(self.pg2.remote_ip4, 0xFFFFFFFF)])
        route.modify(
            [
                VppRoutePath(self.pg1.remote_ip4, 0xFFFFFFFF),
                VppRoutePath(self.pg2.remote_ip4, 0xFFFFFFFF),
            ]
        )
        records, _ = self.collect()
        mine = self.for_prefix(records, "10.20.0.0/16")
        self.assertEqual(len(mine), 1, records)
        r = mine[0]
        self.assertEqual(r["event"], EV_ADD)  # collector never saw it before
        self.assertEqual(r["paths"], 2)  # the state at flush time
        self.assertGreaterEqual(r["count"], 3)
        show = self.vapi.cli("show fib ipfix")
        self.assertIn("coalesced", show)
        route.remove_vpp_config()

    def test_add_remove_before_flush(self):
        """ADD then REMOVE before a flush sends nothing for the prefix"""
        self.wait_templates()
        route = VppIpRoute(
            self, "10.30.0.0", 16, [VppRoutePath(self.pg1.remote_ip4, 0xFFFFFFFF)]
        )
        route.add_vpp_config()
        route.remove_vpp_config()
        records, _ = self.collect()
        self.assertEqual(self.for_prefix(records, "10.30.0.0/16"), [], records)

    def test_remove(self):
        """A removed route is exported as REMOVE with its prefix"""
        self.wait_templates()
        route = VppIpRoute(
            self, "10.40.0.0", 16, [VppRoutePath(self.pg1.remote_ip4, 0xFFFFFFFF)]
        )
        route.add_vpp_config()
        self.collect()
        route.remove_vpp_config()
        records, _ = self.collect()
        mine = self.for_prefix(records, "10.40.0.0/16")
        self.assertEqual(len(mine), 1, records)
        self.assertEqual(mine[0]["event"], EV_REMOVE)
        self.assertEqual(mine[0]["table_id"], 0)

    def test_ip6_and_vrf(self):
        """IPv6 route in a non-default table"""
        self.wait_templates()
        self.vapi.ip_table_add_del(is_add=1, table={"table_id": 7, "is_ip6": 1})
        route = VppIpRoute(
            self,
            "2001:db8:77::",
            48,
            [VppRoutePath(self.pg1.remote_ip6, 0xFFFFFFFF, nh_table_id=0)],
            table_id=7,
        )
        route.add_vpp_config()
        records, _ = self.collect()
        mine = self.for_prefix(records, "2001:db8:77::/48")
        self.assertEqual(len(mine), 1, records)
        self.assertEqual(mine[0]["table_id"], 7)
        self.assertEqual(mine[0]["nh"], ip_address(self.pg1.remote_ip6))
        route.remove_vpp_config()
        self.collect()
        self.vapi.ip_table_add_del(is_add=0, table={"table_id": 7, "is_ip6": 1})

    def test_resync(self):
        """resync re-exports programmed entries as event 4"""
        self.wait_templates()
        route = VppIpRoute(
            self, "10.50.0.0", 16, [VppRoutePath(self.pg1.remote_ip4, 0xFFFFFFFF)]
        )
        route.add_vpp_config()
        self.collect()
        self.vapi.cli("fib ipfix resync")
        records, _ = self.collect()
        mine = self.for_prefix(records, "10.50.0.0/16")
        self.assertEqual(len(mine), 1, records)
        self.assertEqual(mine[0]["event"], EV_RESYNC)
        # the interface routes are there too
        self.assertTrue(
            self.for_prefix(records, "%s/32" % self.pg1.local_ip4), records
        )
        route.remove_vpp_config()

    def test_sequence_numbers(self):
        """IPFIX sequence numbers count data records (RFC 7011 3.1)"""
        self.wait_templates()
        routes = [
            VppIpRoute(
                self,
                "10.60.%d.0" % i,
                24,
                [VppRoutePath(self.pg1.remote_ip4, 0xFFFFFFFF)],
            )
            for i in range(100)
        ]
        for r in routes:
            r.add_vpp_config()
        records, messages = self.collect()
        data_msgs = [m for m in messages if m.records]
        self.assertGreaterEqual(len(data_msgs), 2)  # 100 x 32 B > one 1450 B MTU
        for a, b in zip(data_msgs, data_msgs[1:]):
            if a.domain == b.domain:
                self.assertEqual(b.seq - a.seq, len(a.records))
        self.assertEqual(
            len([r for r in records if str(r["prefix"]).startswith("10.60.")]), 100
        )
        for r in routes:
            r.remove_vpp_config()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
