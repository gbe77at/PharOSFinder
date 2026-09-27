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
