"""Tests des parseurs du moteur (stdlib seulement) : python3 -m unittest discover tests"""
import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "Resources"))
import pharos_finder as pf  # noqa: E402


def ipv4_udp(src, dst, sport, dport, payload=b""):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + udp


def eth(src, etype, payload, dst="ff:ff:ff:ff:ff:ff"):
    mac = lambda m: bytes(int(x, 16) for x in m.split(":"))  # noqa: E731
    return mac(dst) + mac(src) + struct.pack("!H", etype) + payload


class ModelTests(unittest.TestCase):
    def probe(self, title, body=""):
        m = pf.PHAROS_MODEL_RE.search(title or "") or pf.PHAROS_MODEL_RE.search(body)
        return m.group(1).upper() if m else None

    def test_cpe510_cpe710(self):
        self.assertEqual(self.probe("CPE510"), "CPE510")
        self.assertEqual(self.probe("TP-LINK CPE710 5GHz"), "CPE710")
        self.assertEqual(self.probe(None, "<div>cpe710</div>"), "CPE710")

    def test_other_pharos(self):
        for m in ("CPE210", "CPE220", "CPE520", "CPE605", "CPE610", "WBS210", "WBS510"):
            self.assertEqual(self.probe(f"{m} v3.0"), m)

    def test_title_wins_over_body(self):
        self.assertEqual(self.probe("CPE710", "supports CPE510 and CPE710"), "CPE710")

    def test_classify(self):
        d = pf._new_device("x", "50:c7:bf:01:02:03", "192.168.0.254")
        d["model"] = "CPE710"
        pf.classify(d)
        self.assertEqual(d["kind"], "pharos")
        d = pf._new_device("y", "50:c7:bf:01:02:03", "192.168.0.254")
        d["vendor"] = "TP-Link"
        pf.classify(d)
        self.assertEqual(d["kind"], "tplink")


class MacTests(unittest.TestCase):
    def test_norm_mac(self):
        self.assertEqual(pf.norm_mac("50:c7:bf:1:2:3"), "50:c7:bf:01:02:03")
        self.assertIsNone(pf.norm_mac("garbage"))


class ArpTests(unittest.TestCase):
    def test_windows_french(self):
        text = (
            "\r\nInterface : 192.168.3.10 --- 0x5\r\n"
            "  Adresse Internet      Adresse physique      Type\r\n"
            "  192.168.3.1           50-c7-bf-01-02-03     dynamique\r\n"
            "  192.168.3.255         ff-ff-ff-ff-ff-ff     statique\r\n"
            "\r\nInterface : 169.254.10.2 --- 0x1a\r\n"
            "  192.168.0.254         a8-42-a1-aa-bb-cc     dynamique\r\n"
        )
        rows = pf.parse_arp_windows(text, {5: "Ethernet", 26: "Ethernet 2"})
        self.assertIn(("192.168.3.1", "50:c7:bf:01:02:03", "Ethernet"), rows)
        self.assertIn(("192.168.0.254", "a8:42:a1:aa:bb:cc", "Ethernet 2"), rows)

    def test_windows_english(self):
        text = "Interface: 10.0.0.5 --- 0xb\n  Internet Address      Physical Address      Type\n" \
               "  10.0.0.1              00-11-22-33-44-55     dynamic\n"
        self.assertEqual(pf.parse_arp_windows(text, {11: "Wi-Fi"}),
                         [("10.0.0.1", "00:11:22:33:44:55", "Wi-Fi")])

    def test_mac_arp_regex(self):
        m = pf.ARP_RE.search("? (192.168.0.254) at 50:c7:bf:1:2:3 on en11 ifscope [ethernet]")
        self.assertEqual(m.group(1, 2, 3), ("192.168.0.254", "50:c7:bf:1:2:3", "en11"))

    def test_linux_neigh(self):
        m = pf.LINUX_NEIGH.match("192.168.0.254 dev eth0 lladdr 50:c7:bf:01:02:03 REACHABLE")
        self.assertEqual(m.group(1, 2, 3), ("192.168.0.254", "eth0", "50:c7:bf:01:02:03"))


class TcpdumpTests(unittest.TestCase):
    def test_arp_request(self):
        line = ("17:05:12.123456 50:c7:bf:01:02:03 > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), "
                "length 60: Request who-has 192.168.0.1 tell 192.168.0.254, length 46")
        self.assertEqual(pf.parse_tcpdump_line(line), ("50:c7:bf:01:02:03", "192.168.0.254", False))

    def test_tdp(self):
        line = ("17:05:12.123456 50:c7:bf:01:02:03 > ff:ff:ff:ff:ff:ff, ethertype IPv4 (0x0800), "
                "length 120: 10.9.8.7.20002 > 255.255.255.255.20002: UDP, length 78")
        self.assertEqual(pf.parse_tcpdump_line(line), ("50:c7:bf:01:02:03", "10.9.8.7", True))


class RawPacketTests(unittest.TestCase):
    def test_dhcp_discover_gives_mac(self):
        bootp = bytes([1, 1, 6, 0]) + b"\0" * 24 + bytes([0x50, 0xc7, 0xbf, 1, 2, 3]) + b"\0" * 202
        pkt = ipv4_udp("0.0.0.0", "255.255.255.255", 68, 67, bootp)
        self.assertEqual(pf.parse_ipv4_packet(pkt), ("50:c7:bf:01:02:03", None, False))

    def test_tdp_packet(self):
        pkt = ipv4_udp("172.16.9.9", "255.255.255.255", 20002, 20002, b"x" * 20)
        self.assertEqual(pf.parse_ipv4_packet(pkt), (None, "172.16.9.9", True))

    def test_eth_arp(self):
        arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + bytes([0x50, 0xc7, 0xbf, 1, 2, 3]) \
            + socket.inet_aton("192.168.0.254") + b"\0" * 6 + socket.inet_aton("192.168.0.1")
        self.assertEqual(pf.parse_eth_frame(eth("50:c7:bf:01:02:03", 0x0806, arp)),
                         ("50:c7:bf:01:02:03", "192.168.0.254", False))

    def test_eth_ipv4(self):
        frame = eth("50:c7:bf:01:02:03", 0x0800, ipv4_udp("10.1.1.1", "255.255.255.255", 5000, 20002))
        self.assertEqual(pf.parse_eth_frame(frame), ("50:c7:bf:01:02:03", "10.1.1.1", True))


class LanFilterTests(unittest.TestCase):
    def test_lan(self):
        self.assertTrue(pf.is_lan_ip("192.168.0.254"))
        self.assertTrue(pf.is_lan_ip("169.254.3.4"))
        self.assertFalse(pf.is_lan_ip("8.8.8.8"))

    def test_eth_ipv6_mac_only(self):
        frame = eth("50:c7:bf:01:02:03", 0x86DD, b"\x60" + b"\0" * 39, dst="33:33:00:00:00:01")
        self.assertEqual(pf.parse_eth_frame(frame), ("50:c7:bf:01:02:03", None, False))


class SshTests(unittest.TestCase):
    def test_command(self):
        cmd = pf.ssh_command("192.168.0.254", "admin")
        self.assertEqual(cmd[0], "ssh")
        self.assertEqual(cmd[-1], "admin@192.168.0.254")

    def test_rejects_injection(self):
        with self.assertRaises(RuntimeError):
            pf.ssh_command("192.168.0.254", "admin; rm -rf /")


if __name__ == "__main__":
    unittest.main()
