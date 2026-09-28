"""Tests des protocoles constructeurs (finder_vendors) et de leur intégration au moteur."""
import json
import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "Resources"))
import finder_vendors as fv  # noqa: E402
import pharos_finder as pf  # noqa: E402


def ubnt_tlv(t, v):
    return bytes([t]) + struct.pack("!H", len(v)) + v


def ubnt_reply():
    mac = bytes.fromhex("68d79a45aadd")
    body = (ubnt_tlv(0x01, mac) + ubnt_tlv(0x02, mac + socket.inet_aton("10.10.10.166"))
            + ubnt_tlv(0x03, b"U6-Lite.6.6.77.15402") + ubnt_tlv(0x0B, b"AP-Salon")
            + ubnt_tlv(0x0C, b"U6-Lite") + ubnt_tlv(0x15, b"U6-Lite") + ubnt_tlv(0x17, b"\x00"))
    return b"\x01\x00" + struct.pack("!H", len(body)) + body


def nsdp_reply():
    head = struct.pack("!BBH4s6s6sHH4s4s", 1, 2, 0, b"\0" * 4, b"\x11" * 6, bytes.fromhex("08bd4371f6e5"), 0, 1,
                       b"NSDP", b"\0" * 4)

    def tlv(t, v):
        return struct.pack("!HH", t, len(v)) + v
    body = (tlv(0x0001, b"GS108Ev3") + tlv(0x0003, b"switch-bureau") + tlv(0x0004, bytes.fromhex("08bd4371f6e5"))
            + tlv(0x0006, socket.inet_aton("10.10.10.8")) + tlv(0x000b, b"\x01") + tlv(0x000d, b"2.06.24EN"))
    return head + body + b"\xff\xff\x00\x00"


QNAP_XML = """<?xml version="1.0" encoding="UTF-8" ?><QDocRoot version="1.0">
<model><modelName><![CDATA[TS-X53D]]></modelName><internalModelName><![CDATA[TS-X53D]]></internalModelName>
<platform><![CDATA[TS-NASX86]]></platform><displayModelName><![CDATA[TS-453D]]></displayModelName></model>
<firmware><version><![CDATA[5.2.4]]></version><number><![CDATA[3079]]></number><build><![CDATA[20250426]]></build></firmware>
<hostname><![CDATA[NAS-Maison]]></hostname></QDocRoot>"""


class UbntTests(unittest.TestCase):
    def test_parse(self):
        u = fv.parse_ubnt(ubnt_reply())
        self.assertEqual((u["mac"], u["ips"], u["hostname"], u["model"], u["is_default"]),
                         ("68:d7:9a:45:aa:dd", ["10.10.10.166"], "AP-Salon", "U6-Lite", False))
        self.assertTrue(u["firmware"].startswith("U6-Lite.6.6.77"))

    def test_garbage(self):
        self.assertIsNone(fv.parse_ubnt(b"\x05\x00\x00"))


class NsdpTests(unittest.TestCase):
    def test_request_layout(self):
        r = fv.nsdp_read_request(b"\xaa" * 6, seq=7)
        self.assertEqual((r[0], r[1], r[8:14], r[22:24], r[24:28], r[-4:]),
                         (1, 1, b"\xaa" * 6, b"\x00\x07", b"NSDP", b"\xff\xff\x00\x00"))

    def test_parse(self):
        g = fv.parse_nsdp(nsdp_reply())
        self.assertEqual((g["model"], g["name"], g["ip"], g["dhcp"], g["firmware"], g["mac"]),
                         ("GS108Ev3", "switch-bureau", "10.10.10.8", True, "2.06.24EN", "08:bd:43:71:f6:e5"))

    def test_ignores_requests(self):
        self.assertIsNone(fv.parse_nsdp(fv.nsdp_read_request(b"\x01" * 6)))


class QnapTests(unittest.TestCase):
    def test_parse(self):
        q = fv.parse_qnap_xml(QNAP_XML)
        self.assertEqual((q["model"], q["firmware"], q["build"], q["hostname"]),
                         ("TS-453D", "5.2.4", "20250426", "NAS-Maison"))

    def test_not_qnap(self):
        self.assertIsNone(fv.parse_qnap_xml("<html>hello</html>"))


class FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode()

    def read(self):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeOpener:
    """Simule l'OpenAPI Tuya et enregistre les requêtes signées."""

    def __init__(self):
        self.calls = []

    def open(self, req, timeout=None):
        self.calls.append(req)
        path = req.full_url.split(".com", 1)[1]
        if path.startswith("/v1.0/token"):
            return FakeResponse({"success": True, "result": {"access_token": "TOKEN", "expire_time": 7200}})
        if path.startswith("/v1.0/iot-01/associated-users/devices"):
            return FakeResponse({"success": True, "result": {"devices": [
                {"id": "gw1", "name": "Passerelle salon", "category": "wg2", "product_name": "Zigbee Gateway"},
                {"id": "bf1234567890abcdef", "name": "Prise bureau", "category": "cz", "product_name": "Smart Plug"}],
                "has_more": False}})
        if path.startswith("/v1.0/devices/gw1/sub-devices"):
            return FakeResponse({"success": True, "result": [
                {"id": "zb1", "name": "Capteur chambre", "category": "wsdcg", "product_name": "T&H Sensor"}]})
        if "/firmware" in path and req.get_method() == "GET":
            return FakeResponse({"success": True, "result": {"current_version": "1.0.2", "version": "1.1.0",
                                                             "type": 9, "type_desc": "module Wi-Fi",
                                                             "can_upgrade": True, "upgrade_status": 1}})
        if "/firmware/9" in path:
            return FakeResponse({"success": True, "result": True})
        return FakeResponse({"success": False, "code": 1106, "msg": "permission deny"})


class TuyaCloudTests(unittest.TestCase):
    def setUp(self):
        self.op = FakeOpener()
        self.c = fv.TuyaCloud("ID", "SECRET", "eu", opener=self.op)

    def test_token_and_signed_headers(self):
        devs = self.c.devices()
        self.assertEqual(len(devs), 2)
        tok, call = self.op.calls[0], self.op.calls[1]
        self.assertNotIn("Access_token", tok.headers)
        self.assertEqual(call.headers["Access_token"], "TOKEN")
        self.assertEqual(len(call.headers["Sign"]), 64)
        self.assertTrue(call.full_url.startswith("https://openapi.tuyaeu.com/v1.0/iot-01/associated-users/devices?"))

    def test_error_message(self):
        with self.assertRaises(RuntimeError) as e:
            self.c._call("GET", "/v9/nope")
        self.assertIn("permission deny", str(e.exception))

    def test_engine_sync(self):
        pf.DEVICES.clear()
        pf.upsert(mac="84:e3:42:e5:e5:c3", ip="10.10.10.47", tuya={"gw_id": "bf1234567890abcdef", "version": "3.3"})
        pf._CLIENTS["tuya"] = self.c
        try:
            pf.job_tuya_sync()
        finally:
            pf._CLIENTS.pop("tuya", None)
        plug = pf.DEVICES["84:e3:42:e5:e5:c3"]
        self.assertEqual((plug["name"], plug["model"]), ("Prise bureau", "Prise"))
        self.assertTrue(plug["update_available"])
        sensor = pf.DEVICES["tuya:zb1"]
        self.assertEqual((sensor["name"], sensor["model"], sensor["ip"], sensor["tuya"]["parent"]),
                         ("Capteur chambre", "Capteur température/humidité", None, "Passerelle salon"))
        acts = [a["id"] for a in pf.device_actions(plug)]
        self.assertIn("tuya:upgrade:9", acts)


def dns_name(n):
    return b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\0"


def qnap_mdns_response(ip="10.10.10.5", port=8443):
    inst = "NAS-TVS882T._qdiscover._tcp.local"
    txt = b"".join(bytes([len(x)]) + x for x in (b"accessType=https", f"accessPort={port}".encode(),
                                                 b"model=TVS-X82T", b"displayModel=TVS-882T",
                                                 b"fwVer=5.2.4", b"fwBuildNum=20250426"))
    ptr = dns_name("_qdiscover._tcp.local") + struct.pack("!HHIH", 12, 1, 120, len(dns_name(inst))) + dns_name(inst)
    srv_rd = struct.pack("!HHH", 0, 0, port) + dns_name("NAS-TVS882T.local")
    srv = dns_name(inst) + struct.pack("!HHIH", 33, 0x8001, 120, len(srv_rd)) + srv_rd
    tx = dns_name(inst) + struct.pack("!HHIH", 16, 0x8001, 120, len(txt)) + txt
    a = dns_name("NAS-TVS882T.local") + struct.pack("!HHIH", 1, 0x8001, 120, 4) + socket.inet_aton(ip)
    return struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 3) + ptr + srv + tx + a


class MdnsQnapTests(unittest.TestCase):
    def test_srv_txt(self):
        r = pf.parse_mdns(qnap_mdns_response())
        self.assertEqual(r["ports"]["_qdiscover._tcp"], 8443)
        self.assertEqual(r["txt"]["_qdiscover._tcp"]["displayModel"], "TVS-882T")
        self.assertEqual(r["hosts"], {"10.10.10.5": "NAS-TVS882T"})

    def test_web_from_announce(self):
        r = pf.parse_mdns(qnap_mdns_response(port=5443))
        self.assertEqual(pf.web_from_mdns("10.10.10.5", r["ports"], r["txt"]), "https://10.10.10.5:5443/")
        self.assertEqual(pf.web_from_mdns("10.0.0.9", {"_http._tcp": 8123}, {}), "http://10.0.0.9:8123/")
        self.assertIsNone(pf.web_from_mdns("10.0.0.9", {}, {}))

    def test_svc_of(self):
        self.assertEqual(pf._svc_of("My NAS._qdiscover._tcp.local"), "_qdiscover._tcp")
        self.assertIsNone(pf._svc_of("host.local"))


class VendorDbTests(unittest.TestCase):
    def test_offline_registry(self):
        for mac, want in (("24:5e:be:1a:1f:af", "QNAP"), ("0c:43:f9:99:25:b4", "Amazon"), ("08:bd:43:71:f6:e5", "NETGEAR"),
                          ("68:d7:9a:45:aa:dd", "Ubiquiti"), ("c4:82:e1:8d:5a:7b", "Tuya"), ("cc:32:e5:9d:a9:a4", "TP-Link")):
            self.assertIn(want, pf.vendor_of(mac))

    def test_classification_without_network(self):
        pf.DEVICES.clear()
        d = pf.upsert(mac="24:5e:be:1a:1f:af", ip="10.10.10.5")
        self.assertEqual(d["kind"], "qnap")


class TuyaSenderTests(unittest.TestCase):
    def test_sender_ip_wins_and_no_false_conflict(self):
        pf.DEVICES.clear()
        pf.CONFLICTS.clear()
        pf.upsert(mac="c4:82:e1:8d:4d:ed", ip="10.10.10.48")
        pf.upsert(mac="c4:82:e1:8d:5a:7b", ip="10.10.10.63")
        body = json.dumps({"ip": "10.10.10.48", "gwId": "bf2b", "version": "3.3"}).encode()
        frame = b"\x00\x00\x55\xaa" + struct.pack("!III", 0, 0x13, len(body) + 12) + b"\0" * 4 + body + b"\0" * 4 \
            + b"\x00\x00\xaa\x55"
        pf.handle_tuya(frame, "10.10.10.63", 6666)
        self.assertEqual(pf.DEVICES["c4:82:e1:8d:5a:7b"]["tuya"]["gw_id"], "bf2b")
        self.assertIsNone(pf.DEVICES["c4:82:e1:8d:4d:ed"]["tuya"])
        self.assertFalse(pf.CONFLICTS)


class EngineIntegrationTests(unittest.TestCase):
    def test_classify_vendors(self):
        for vendor, kind in (("Ubiquiti Inc", "unifi"), ("NETGEAR", "netgear"), ("QNAP Systems, Inc.", "qnap")):
            d = pf._new_device("x", "00:11:22:33:44:55", "10.0.0.2")
            d["vendor"] = vendor
            pf.classify(d)
            self.assertEqual(d["kind"], kind)

    def test_unifi_actions(self):
        d = pf._new_device("x", "68:d7:9a:45:aa:dd", "10.10.10.166")
        d["kind"] = "unifi"
        d["unifi"] = {"controller": True, "upgradable": True, "latest": "6.7.1", "adopted": True}
        ids = [a["id"] for a in pf.device_actions(d)]
        self.assertEqual(ids, ["web", "unifi:set-locate", "unifi:unset-locate", "unifi:restart", "unifi:upgrade"])

    def test_help_present(self):
        self.assertIn("platform.tuya.com", pf.HELP["tuya"])
        self.assertIn("Link App Account", pf.HELP["tuya"])


if __name__ == "__main__":
    unittest.main()


BAMBU_NOTIFY = (b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nServer: UPnP/1.0\r\nLocation: 10.10.10.77\r\n"
                b"NT: urn:bambulab-com:device:3dprinter:1\r\nUSN: 22E8BJ5B1001755\r\nCache-Control: max-age=1800\r\n"
                b"DevModel.bambu.com: N7\r\nDevName.bambu.com: P2S\r\nDevSignal.bambu.com: -45\r\n"
                b"DevConnect.bambu.com: cloud\r\nDevBind.bambu.com: occupied\r\nDevVersion.bambu.com: 01.02.00.00\r\n\r\n")


class Printer3DTests(unittest.TestCase):
    def test_bambu_notify(self):
        b = fv.parse_bambu_notify(BAMBU_NOTIFY)
        self.assertEqual((b["ip"], b["serial"], b["model"], b["connect"], b["firmware"]),
                         ("10.10.10.77", "22E8BJ5B1001755", "P2S", "cloud", "01.02.00.00"))

    def test_unknown_code_kept_verbatim(self):
        b = fv.parse_bambu_notify(BAMBU_NOTIFY.replace(b"N7", b"Z9"))
        self.assertEqual(b["model"], "Z9")

    def test_other_ssdp_ignored(self):
        self.assertIsNone(fv.parse_bambu_notify(b"NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\nUSN: uuid:x\r\n"))

    def test_moonraker(self):
        r = fv.parse_moonraker({"result": {"hostname": "K2Pro-EB11", "software_version": "09faed31-dirty",
                                           "state": "ready"}},
                               {"result": {"system_info": {"distribution": {"name": "OpenWrt 21.02"}}}})
        self.assertEqual((r["brand"], r["model"], r["state"], r["distro"]),
                         ("Creality", "K2 Pro", "ready", "OpenWrt 21.02"))
        delta = fv.parse_moonraker({"result": {"hostname": "printer"}}, None,
                                   {"result": {"status": {"configfile": {"settings": {"printer": {"kinematics": "delta"}}}}}})
        self.assertEqual(delta["brand"], "Klipper (delta)")
        self.assertIsNone(fv.parse_moonraker({"result": {"foo": 1}}))

    def test_printer_kind_wins_over_module_vendor(self):
        pf.DEVICES.clear()
        pf.upsert(mac="60:32:3b:e9:c7:3a", ip="10.10.10.77")   # module Wi-Fi Quectel
        d = pf.upsert(ip="10.10.10.77", source="SSDP Bambu", model="Bambu Lab P2S",
                      printer3d={"brand": "Bambu Lab", "mode": "cloud"})
        self.assertEqual((d["kind"], d["mac"]), ("printer3d", "60:32:3b:e9:c7:3a"))


class RealWorldTests(unittest.TestCase):
    """Valeurs relevées sur le réseau de l'auteur (2026-09-28)."""

    def test_qnap_txt_single_string(self):
        inst = "NAS-TVS882T._qdiscover._tcp.local"
        txt = b"accessType=https,accessPort=51443,model=TS-X82,displayModel=TVS-882T,fwVer=5.2.10,fwBuildNum=20260731"
        rr = dns_name(inst) + struct.pack("!HHIH", 16, 0x8001, 120, len(txt) + 1) + bytes([len(txt)]) + txt
        r = pf.parse_mdns(struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + rr)
        q = r["txt"]["_qdiscover._tcp"]
        self.assertEqual((q["accessPort"], q["displayModel"], q["fwVer"]), ("51443", "TVS-882T", "5.2.10"))
        self.assertEqual(pf.web_from_mdns("10.10.10.5", {"_qdiscover._tcp": 51080}, r["txt"]),
                         "https://10.10.10.5:51443/")

    def test_flsun_hostname(self):
        r = fv.parse_moonraker({"result": {"hostname": "FLSunV400Max", "state": "ready"}},
                               {"result": {"system_info": {"distribution": {"name": "Debian GNU/Linux 10 (buster)"}}}},
                               {"result": {"status": {"configfile": {"settings": {"printer": {"kinematics": "delta"}}}}}})
        self.assertEqual((r["brand"], r["model"], r["kinematics"]), ("FLSun", "V400 Max", "delta"))

    def test_mdns_query_types(self):
        pkt = pf.mdns_query_packet(["NAS-TVS882T._qdiscover._tcp"], 16)
        self.assertTrue(pkt.endswith(struct.pack("!HH", 16, 0x8001)))
