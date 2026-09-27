"""Tests des parseurs du moteur (stdlib seulement) : python3 -m unittest discover tests"""
import json
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


class Ipv6Tests(unittest.TestCase):
    def test_mac_ndp(self):
        out = ("Neighbor                        Linklayer Address  Netif Expire    St Flgs Prbs\n"
               "fe80::52c7:bfff:fe01:203%en11   50:c7:bf:1:2:3     en11 23h59m58s S\n"
               "fe80::1%en0                     8:bd:43:71:f6:e5   en0  permanent R\n")
        rows = [(a, m, i) for a, sc, m, i in pf.NDP_MAC.findall(out)]
        self.assertIn(("fe80::52c7:bfff:fe01:203", "50:c7:bf:1:2:3", "en11"), rows)

    def test_windows_netsh(self):
        out = "Adresse Internet                              Adresse physique   Type\n" \
              "--------------------------------------------  -----------------  -----------\n" \
              "fe80::52c7:bfff:fe01:203                      50-c7-bf-01-02-03  Accessible\n"
        self.assertEqual(pf.NETSH_V6.findall(out), [("fe80::52c7:bfff:fe01:203", "50-c7-bf-01-02-03")])

    def test_linux_neigh(self):
        out = "fe80::52c7:bfff:fe01:203 lladdr 50:c7:bf:01:02:03 STALE\n"
        self.assertEqual(pf.LINUX_V6.findall(out), [("fe80::52c7:bfff:fe01:203", "50:c7:bf:01:02:03")])

    def test_ssh_ipv6(self):
        self.assertEqual(pf.ssh_command("fe80::1%en11", "admin")[-1], "admin@fe80::1%en11")
        with self.assertRaises(RuntimeError):
            pf.ssh_command("fe80::1%en11;ls", "admin")


# Annonce CDP réelle d'un CPE510 v3.0 (firmware 2.2.3), capturée sur le terrain.
CPE510_CDP = bytes.fromhex(
    "01000ccccccccc32e59da9a4007caaaa0300000c2000017836a30001000a43504535313000020011000000010101cc"
    "0004c0a800fe00040008000000020005002a322e322e33204275696c642032303230313032382052656c2e2035353232"
    "30202834353535290006001754502d4c494e4b204350453531302076332e300003000762723000ff00052e")


class DiscoveryTests(unittest.TestCase):
    def test_cdp_cpe510(self):
        info = pf.parse_discovery(CPE510_CDP)
        self.assertEqual(info["proto"], "CDP")
        self.assertEqual(info["mac"], "cc:32:e5:9d:a9:a4")
        self.assertEqual(info["ip"], "192.168.0.254")
        self.assertEqual(info["name"], "CPE510")
        self.assertEqual(info["platform"], "TP-LINK CPE510 v3.0")
        self.assertTrue(info["firmware"].startswith("2.2.3 Build 20201028"))

    def test_cdp_creates_pharos_device(self):
        pf.DEVICES.clear()
        pf.handle_discovery_frame(CPE510_CDP, "en11")
        d = pf.DEVICES["cc:32:e5:9d:a9:a4"]
        self.assertEqual((d["ip"], d["model"], d["kind"], d["announced"]), ("192.168.0.254", "CPE510", "pharos", "CDP"))

    def test_lldp(self):
        def tlv(t, v):
            return struct.pack("!H", (t << 9) | len(v)) + v
        body = tlv(5, b"CPE710") + tlv(6, b"TP-LINK CPE710 v1.0") \
            + tlv(8, bytes([5, 1]) + socket.inet_aton("172.20.1.9") + b"\x02\0\0\0\0\0") + tlv(0, b"")
        frame = eth("6c:4c:bc:2a:3b:d0", 0x88CC, body, dst="01:80:c2:00:00:0e")
        info = pf.parse_discovery(frame)
        self.assertEqual((info["proto"], info["ip"], info["platform"]), ("LLDP", "172.20.1.9", "TP-LINK CPE710 v1.0"))

    def test_other_frames_ignored(self):
        self.assertIsNone(pf.parse_discovery(eth("50:c7:bf:01:02:03", 0x0800, b"\0" * 40)))

    def test_ip_conflict_flagged(self):
        pf.DEVICES.clear()
        pf.upsert(mac="cc:32:e5:9d:a9:a4", ip="192.168.0.254")
        pf.upsert(mac="6c:4c:bc:2a:3b:d0", ip="192.168.0.254")
        self.assertIn(("192.168.0.254", "6c:4c:bc:2a:3b:d0"), pf.CONFLICTS)


class PcapTests(unittest.TestCase):
    def test_stream(self):
        import io
        head = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        rec = struct.pack("<IIII", 0, 0, len(CPE510_CDP), len(CPE510_CDP)) + CPE510_CDP
        self.assertEqual(list(pf.iter_pcap(io.BytesIO(head + rec + rec))), [CPE510_CDP, CPE510_CDP])


def tuya_frame(body, retcode=True, prefix=b"\x00\x00\x55\xaa", suffix=b"\x00\x00\xaa\x55"):
    body = (b"\0" * 4 if retcode else b"") + body
    return prefix + struct.pack("!III", 0, 0x13, len(body) + 8) + body + b"\0" * 4 + suffix


def ecb_encrypt(key, data):
    pad = 16 - len(data) % 16
    data += bytes([pad]) * pad
    rk = pf._aes_expand(key)
    return b"".join(pf.aes_encrypt_block(rk, data[i:i + 16]) for i in range(0, len(data), 16))


class AesTests(unittest.TestCase):
    def test_fips197(self):
        rk = pf._aes_expand(bytes(range(16)))
        ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(pf.aes_encrypt_block(rk, bytes.fromhex("00112233445566778899aabbccddeeff")), ct)
        self.assertEqual(pf.aes_decrypt_block(rk, ct), bytes.fromhex("00112233445566778899aabbccddeeff"))

    def test_gcm_ctr_vector(self):  # vecteur 3 de la spécification GCM (McGrew & Viega)
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
        iv = bytes.fromhex("cafebabefacedbaddecaf888")
        ct = bytes.fromhex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                           "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985")
        pt = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                           "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
        self.assertEqual(pf.aes_gcm_decrypt_unverified(key, iv, ct), pt)


class TuyaTests(unittest.TestCase):
    INFO = {"ip": "10.10.10.47", "gwId": "bf1234567890abcdef", "active": 2, "encrypt": True,
            "productKey": "keyabc123", "version": "3.3"}

    def test_v31_plain(self):
        body = json.dumps(dict(self.INFO, version="3.1")).encode()
        self.assertEqual(pf.parse_tuya_broadcast(tuya_frame(body), 6666)["gwId"], "bf1234567890abcdef")

    def test_v33_encrypted(self):
        body = ecb_encrypt(pf.TUYA_UDP_KEY, json.dumps(self.INFO).encode())
        for rc in (True, False):
            obj = pf.parse_tuya_broadcast(tuya_frame(body, retcode=rc), 6667)
            self.assertEqual((obj["ip"], obj["productKey"]), ("10.10.10.47", "keyabc123"))

    def test_v35_gcm(self):
        iv = bytes(range(12))
        plain = json.dumps(dict(self.INFO, version="3.5")).encode()
        rk = pf._aes_expand(pf.TUYA_UDP_KEY)
        enc = bytearray()
        for i in range(0, len(plain), 16):
            ks = pf.aes_encrypt_block(rk, iv + (i // 16 + 2).to_bytes(4, "big"))
            enc += bytes(a ^ b for a, b in zip(plain[i:i + 16], ks))
        frame = b"\x00\x00\x66\x99" + b"\0\0" + struct.pack("!III", 0, 0x13, 0) + iv + bytes(enc) \
            + b"\0" * 16 + b"\x00\x00\x99\x66"
        self.assertEqual(pf.parse_tuya_broadcast(frame, 7000)["version"], "3.5")

    def test_garbage(self):
        self.assertIsNone(pf.parse_tuya_broadcast(b"hello", 6667))

    def test_handle_creates_tuya_device(self):
        pf.DEVICES.clear()
        body = ecb_encrypt(pf.TUYA_UDP_KEY, json.dumps(self.INFO).encode())
        pf.handle_tuya(tuya_frame(body), "10.10.10.47", 6667)
        d = next(iter(pf.DEVICES.values()))
        self.assertEqual((d["kind"], d["ip"], d["tuya"]["gw_id"]), ("tuya", "10.10.10.47", "bf1234567890abcdef"))

    def test_merges_with_known_mac(self):
        pf.DEVICES.clear()
        pf.upsert(mac="84:e3:42:e5:e5:c3", ip="10.10.10.47")
        pf.upsert(ip="10.10.10.47", source="Tuya", tuya={"gw_id": "x"})
        self.assertEqual(list(pf.DEVICES), ["84:e3:42:e5:e5:c3"])


def mdns_response(name, service, ip):
    def enc(n):
        return b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\0"
    ptr = enc(service + ".local") + struct.pack("!HHIH", 12, 1, 120, len(enc(name + "." + service + ".local"))) \
        + enc(name + "." + service + ".local")
    a = enc("firetv.local") + struct.pack("!HHIH", 1, 0x8001, 120, 4) + socket.inet_aton(ip)
    return struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 1) + ptr + a


class MdnsTests(unittest.TestCase):
    def test_query_packet(self):
        pkt = pf.mdns_query_packet(("_amzn-wplay._tcp",))
        self.assertEqual(struct.unpack("!H", pkt[4:6])[0], 1)
        self.assertIn(b"\x0b_amzn-wplay\x04_tcp\x05local\x00", pkt)

    def test_parse(self):
        r = pf.parse_mdns(mdns_response("Fire TV de Guillaume", "_amzn-wplay._tcp", "10.10.10.80"))
        self.assertEqual(r["instances"], [("_amzn-wplay._tcp", "Fire TV de Guillaume")])
        self.assertEqual(r["hosts"], {"10.10.10.80": "firetv"})


class AmazonTests(unittest.TestCase):
    def test_models(self):
        self.assertEqual(pf.amazon_model([], ["_amzn-wplay._tcp"]), "Fire TV")
        self.assertEqual(pf.amazon_model([55443], []), "Echo")
        self.assertEqual(pf.amazon_model([4070], []), "Echo")
        self.assertEqual(pf.amazon_model([], []), "Amazon")

    def test_classify(self):
        d = pf._new_device("x", "40:a9:cf:63:c1:25", "10.10.10.80")
        d["vendor"] = "Amazon Technologies Inc."
        pf.classify(d)
        self.assertEqual(d["kind"], "amazon")
        d = pf._new_device("y", "84:e3:42:e5:e5:c3", "10.10.10.47")
        d["vendor"] = "Tuya Smart Inc."
        pf.classify(d)
        self.assertEqual(d["kind"], "tuya")


class SnapshotTests(unittest.TestCase):
    def test_all_kinds_serialize(self):
        pf.DEVICES.clear()
        pf.upsert(mac="cc:32:e5:9d:a9:a4", ip="192.168.0.254", model="CPE510")
        pf.upsert(mac="84:e3:42:e5:e5:c3", ip="10.10.10.47", tuya={"gw_id": "x", "version": "3.3"})
        pf.upsert(mac="40:a9:cf:63:c1:25", ip="10.10.10.80", vendor="Amazon Technologies Inc.")
        pf.upsert(mac="02:00:00:00:00:01", ip=None)
        snap = pf.snapshot()
        json.dumps(snap)
        self.assertEqual([d["kind"] for d in snap["devices"]], ["pharos", "tuya", "amazon", "other"])


class SshTests(unittest.TestCase):
    def test_command(self):
        cmd = pf.ssh_command("192.168.0.254", "admin")
        self.assertEqual(cmd[0], "ssh")
        self.assertEqual(cmd[-1], "admin@192.168.0.254")

    def test_rejects_injection(self):
        with self.assertRaises(RuntimeError):
            pf.ssh_command("192.168.0.254", "admin; rm -rf /")


@unittest.skipUnless(pf.IS_WIN, "Windows seulement")
class WindowsInterfaceTests(unittest.TestCase):
    def test_api_matches_powershell(self):
        api = {i["name"]: i for i in pf._windows_interfaces_api()}
        ps = {i["name"]: i for i in pf._windows_interfaces_ps()}
        print("\nAPI:", api, "\nPS:", ps)
        self.assertTrue(any(i["active"] and i["ipv4"] for i in api.values()))
        for name, i in ps.items():
            if name in api:
                self.assertEqual(api[name]["mac"], i["mac"])
                self.assertEqual({a["ip"] for a in api[name]["ipv4"]}, {a["ip"] for a in i["ipv4"]})


if __name__ == "__main__":
    unittest.main()
