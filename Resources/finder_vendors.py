"""
Protocoles constructeurs pour Pharos Finder (stdlib uniquement, sans dépendance au moteur).

- UniFi / Ubiquiti : découverte UDP 10001 (TLV) et API du contrôleur UniFi Network.
- NETGEAR : NSDP (UDP 63322/63324), lecture seule.
- QNAP : /cgi-bin/authLogin.cgi (XML public : modèle, firmware, nom).
- Tuya : OpenAPI cloud (signature HMAC-SHA256), appareils, sous-appareils, firmware.

Toutes les fonctions réseau prennent des paramètres explicites et renvoient des données :
le moteur (pharos_finder.py) les appelle et intègre les résultats.
"""

import hashlib
import hmac
import http.cookiejar
import json
import re
import socket
import ssl
import struct
import time
import urllib.parse
import urllib.request
import uuid


def _insecure_ctx():
    """Les équipements et contrôleurs locaux ont des certificats auto-signés."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _mac(b):
    return ":".join(f"{x:02x}" for x in b)


# ─────────────────────────── UniFi : découverte UDP 10001 ───────────────────────────

UBNT_PORT = 10001
UBNT_REQUEST = b"\x01\x00\x00\x00"   # version 1, demande de découverte, longueur 0


def parse_ubnt(data):
    """Réponse de découverte Ubiquiti → dict ou None.
    En-tête : version(1) commande(1) longueur(2) ; puis TLV type(1) longueur(2) valeur."""
    if len(data) < 4 or data[0] not in (1, 2):
        return None
    total = struct.unpack("!H", data[2:4])[0]
    body = data[4:4 + total]
    info = {"mac": None, "ips": [], "firmware": None, "hostname": None, "platform": None,
            "model": None, "essid": None, "serial": None, "uptime": None, "is_default": None}
    p = 0
    while p + 3 <= len(body):
        t, ln = body[p], struct.unpack("!H", body[p + 1:p + 3])[0]
        v = body[p + 3:p + 3 + ln]
        p += 3 + ln
        txt = v.decode("utf-8", "ignore").strip("\x00 ")
        if t == 0x01 and ln == 6:
            info["mac"] = _mac(v)
        elif t == 0x02 and ln == 10:
            info["mac"] = info["mac"] or _mac(v[:6])
            info["ips"].append(socket.inet_ntoa(v[6:10]))
        elif t == 0x03:
            info["firmware"] = txt
        elif t == 0x0A and ln in (4, 8):
            info["uptime"] = int.from_bytes(v, "big")
        elif t == 0x0B:
            info["hostname"] = txt
        elif t == 0x0C:
            info["platform"] = txt
        elif t == 0x0D:
            info["essid"] = txt
        elif t == 0x13:
            info["serial"] = txt
        elif t in (0x14, 0x15):
            info["model"] = info["model"] or txt
        elif t == 0x17 and ln >= 1:
            info["is_default"] = bool(v[0])
    return info if info["mac"] else None


def ubnt_model_label(info):
    """Nom lisible : « UniFi U6-Lite (firmware 6.6.77) »."""
    return info.get("model") or info.get("platform") or "UniFi"


# ─────────────────────────── NETGEAR : NSDP ───────────────────────────

NSDP_PORTS = ((63321, 63322), (63323, 63324))   # (port local, port des switchs)
NSDP_READ_TLVS = (0x0001, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x000b, 0x000d, 0x000e, 0x000f)


def nsdp_read_request(host_mac, seq=1, device_mac=b"\x00" * 6, tlvs=NSDP_READ_TLVS):
    head = struct.pack("!BBH4s6s6sHH4s4s", 1, 1, 0, b"\x00" * 4, host_mac, device_mac, 0, seq,
                       b"NSDP", b"\x00" * 4)
    return head + b"".join(struct.pack("!HH", t, 0) for t in tlvs) + b"\xff\xff\x00\x00"


def parse_nsdp(data):
    """Réponse de lecture NSDP → dict ou None."""
    if len(data) < 36 or data[0] != 1 or data[1] != 2 or data[24:28] != b"NSDP":
        return None
    info = {"device_mac": _mac(data[14:20]), "model": None, "name": None, "mac": None, "location": None,
            "ip": None, "netmask": None, "gateway": None, "dhcp": None, "firmware": None,
            "firmware2": None, "active_slot": None}
    p = 32
    while p + 4 <= len(data):
        t, ln = struct.unpack("!HH", data[p:p + 4])
        if t == 0xFFFF:
            break
        v = data[p + 4:p + 4 + ln]
        p += 4 + ln
        txt = v.decode("utf-8", "ignore").strip("\x00 ")
        if t == 0x0001:
            info["model"] = txt
        elif t == 0x0003:
            info["name"] = txt
        elif t == 0x0004 and ln == 6:
            info["mac"] = _mac(v)
        elif t == 0x0005:
            info["location"] = txt
        elif t in (0x0006, 0x0007, 0x0008) and ln == 4:
            info[{6: "ip", 7: "netmask", 8: "gateway"}[t]] = socket.inet_ntoa(v)
        elif t == 0x000B and ln >= 1:
            info["dhcp"] = v[0] == 1
        elif t == 0x000D:
            info["firmware"] = txt
        elif t == 0x000E:
            info["firmware2"] = txt
        elif t == 0x000F and ln >= 1:
            info["active_slot"] = v[0]
    info["mac"] = info["mac"] or info["device_mac"]
    return info


def _bind_to_iface(s, ifindex):
    """macOS : IP_BOUND_IF force l'interface de sortie des broadcasts."""
    if ifindex:
        try:
            s.setsockopt(socket.IPPROTO_IP, 25, ifindex)
        except OSError:
            pass


def nsdp_discover(host_mac, wait=3.0, bind_ip="", ifindex=None):
    """Diffuse une lecture NSDP sur les deux couples de ports ; renvoie la liste des réponses."""
    socks = []
    for local, remote in NSDP_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        _bind_to_iface(s, ifindex)
        try:
            s.bind((bind_ip, local))
        except OSError:
            s.close()
            continue
        try:
            s.sendto(nsdp_read_request(host_mac, seq=1), ("255.255.255.255", remote))
        except OSError:
            s.close()
            continue
        socks.append(s)
    time.sleep(0.4)   # 2e envoi : certains switchs (GS108PE) ignorent parfois le premier
    for s, (_, remote) in zip(socks, [pr for pr in NSDP_PORTS]):
        try:
            s.sendto(nsdp_read_request(host_mac, seq=2), ("255.255.255.255", remote))
        except OSError:
            pass
    return _collect(socks, wait, parse_nsdp)


def _collect(socks, wait, parser):
    import select
    found, end = {}, time.time() + wait
    try:
        while socks and time.time() < end:
            ready, _, _ = select.select(socks, [], [], 0.3)
            for s in ready:
                try:
                    data, addr = s.recvfrom(4096)
                except OSError:
                    continue
                info = parser(data)
                if info:
                    info.setdefault("sender", addr[0])
                    found[info.get("mac") or addr[0]] = info
    finally:
        for s in socks:
            s.close()
    return list(found.values())


def ubnt_discover(wait=3.0, bind_ip="", ifindex=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    _bind_to_iface(s, ifindex)
    s.bind((bind_ip, 0))
    for dest in ("255.255.255.255", "233.89.188.1"):
        try:
            s.sendto(UBNT_REQUEST, (dest, UBNT_PORT))
        except OSError:
            pass
    return _collect([s], wait, parse_ubnt)


# ─────────────────────────── QNAP ───────────────────────────

QNAP_PORTS = ((8080, "http"), (443, "https"), (5000, "http"), (5001, "https"), (80, "http"),
              (8081, "http"), (8443, "https"), (9443, "https"))


def parse_qnap_xml(text):
    def tag(name):
        m = re.search(rf"<{name}>\s*(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?\s*</{name}>", text, re.S | re.I)
        return m.group(1).strip() if m else None
    model = tag("displayModelName") or tag("modelName")
    if not model and not tag("webAccessPort"):   # QTS 5 ne donne plus le modèle sans connexion
        return None
    port, sport = tag("webAccessPort"), tag("stunnelPort")
    return {"model": model, "internal_model": tag("internalModelName"), "firmware": tag("version"),
            "build": tag("build"), "hostname": tag("hostname"), "platform": tag("platform"),
            "http_port": int(port) if port and port.isdigit() else None,
            "https_port": int(sport) if sport and sport.isdigit() and tag("stunnelEnabled") != "0" else None}


def qnap_probe(ip, timeout=4, first=None):
    """Lit modèle / firmware / nom d'un NAS QNAP via la page publique authLogin.cgi.
    `first` : adresse web annoncée par le NAS (mDNS), essayée en premier."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=_insecure_ctx()))
    candidates = []
    if first:
        u = urllib.parse.urlparse(first)
        if u.port:
            candidates.append((u.port, u.scheme))
    candidates += [c for c in QNAP_PORTS if c not in candidates]
    for port, scheme in candidates:
        try:
            with socket.create_connection((ip, port), timeout=1):
                pass
        except OSError:
            continue
        url = f"{scheme}://{ip}:{port}/cgi-bin/authLogin.cgi"
        try:
            with opener.open(url, timeout=timeout) as r:
                info = parse_qnap_xml(r.read(20000).decode("utf-8", "ignore"))
        except Exception:
            continue
        if info:
            info["web"] = f"{scheme}://{ip}:{port}/"
            return info
    return None


# ─────────────────────────── Tuya OpenAPI ───────────────────────────

TUYA_REGIONS = {
    "eu": "https://openapi.tuyaeu.com", "weu": "https://openapi-weaz.tuyaeu.com",
    "us": "https://openapi.tuyaus.com", "eus": "https://openapi-ueaz.tuyaus.com",
    "cn": "https://openapi.tuyacn.com", "in": "https://openapi.tuyain.com",
}

# Catégories Tuya courantes → libellé
TUYA_CATEGORIES = {
    "wg2": "Passerelle Zigbee", "wg": "Passerelle", "wfcon": "Passerelle Wi-Fi", "zwjcy": "Capteur sol",
    "cz": "Prise", "pc": "Multiprise", "kg": "Interrupteur", "tdq": "Disjoncteur", "dlq": "Disjoncteur",
    "dj": "Ampoule", "dd": "Ruban LED", "fwd": "Éclairage d'ambiance", "dc": "Guirlande", "xdd": "Plafonnier",
    "wsdcg": "Capteur température/humidité", "mcs": "Capteur d'ouverture", "pir": "Détecteur de mouvement",
    "sj": "Détecteur de fuite", "ywbj": "Détecteur de fumée", "rqbj": "Détecteur de gaz", "cobj": "Détecteur CO",
    "ldcg": "Capteur de luminosité", "hps": "Détecteur de présence", "wkcz": "Contrôleur", "wxkg": "Bouton sans fil",
    "cl": "Rideau / volet", "clkg": "Interrupteur de volet", "wk": "Thermostat", "wkf": "Vanne thermostatique",
    "sp": "Caméra", "ms": "Serrure", "mc": "Contact de porte", "bh": "Bouilloire", "kt": "Climatiseur",
    "qn": "Radiateur", "cs": "Déshumidificateur", "jsq": "Humidificateur", "kj": "Purificateur d'air",
    "fs": "Ventilateur", "sd": "Aspirateur robot", "zndb": "Compteur d'énergie", "dlq_dl": "Compteur",
    "ggq": "Arrosage", "sfkzq": "Vanne d'eau", "cwwsq": "Distributeur animaux", "sgbj": "Sirène",
    "bxx": "Coffre", "qt": "Autre",
}


class TuyaCloud:
    """Client minimal de l'OpenAPI Tuya (signature « nouvelle méthode » HMAC-SHA256)."""

    def __init__(self, access_id, access_secret, region="eu", opener=None):
        self.id, self.secret = access_id.strip(), access_secret.strip()
        self.base = TUYA_REGIONS.get(region, region if region.startswith("https://") else TUYA_REGIONS["eu"])
        self.token, self.token_exp = None, 0
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}))

    @staticmethod
    def string_to_sign(method, path, query=None, body=b""):
        url = path
        if query:
            url += "?" + "&".join(f"{k}={query[k]}" for k in sorted(query))
        return f"{method}\n{hashlib.sha256(body).hexdigest()}\n\n{url}", url

    def sign(self, t, nonce, string_to_sign, token=""):
        msg = self.id + token + t + nonce + string_to_sign
        return hmac.new(self.secret.encode(), msg.encode(), hashlib.sha256).hexdigest().upper()

    def _call(self, method, path, query=None, body=None, auth=True):
        raw = json.dumps(body).encode() if body is not None else b""
        sts, url = self.string_to_sign(method, path, query, raw)
        t, nonce = str(int(time.time() * 1000)), uuid.uuid4().hex
        token = self._ensure_token() if auth else ""
        headers = {"client_id": self.id, "t": t, "nonce": nonce, "sign_method": "HMAC-SHA256",
                   "sign": self.sign(t, nonce, sts, token), "Content-Type": "application/json"}
        if auth:
            headers["access_token"] = token
        req = urllib.request.Request(self.base + url, data=raw or None, method=method, headers=headers)
        with self.opener.open(req, timeout=15) as r:
            res = json.loads(r.read().decode("utf-8"))
        if not res.get("success"):
            code = res.get("code") or res.get("error_code")
            msg = res.get("msg") or res.get("error_msg")
            raise RuntimeError(f"Tuya {code} : {msg}")
        return res.get("result")

    def _ensure_token(self):
        if not self.token or time.time() > self.token_exp - 60:
            r = self._call("GET", "/v1.0/token", {"grant_type": "1"}, auth=False)
            self.token, self.token_exp = r["access_token"], time.time() + int(r.get("expire_time", 7200))
        return self.token

    def devices(self):
        """Tous les appareils des comptes Smart Life liés au projet."""
        out, last = [], ""
        for _ in range(50):
            q = {"size": "100"}
            if last:
                q["last_row_key"] = last
            r = self._call("GET", "/v1.0/iot-01/associated-users/devices", q)
            out += r.get("devices", [])
            last = r.get("last_row_key") or ""
            if not r.get("has_more") or not last:
                break
        return out

    def sub_devices(self, gateway_id):
        try:
            return self._call("GET", f"/v1.0/devices/{gateway_id}/sub-devices") or []
        except Exception:
            return self._call("GET", f"/v1.0/iot-03/device-registration/devices/{gateway_id}/sub-devices") or []

    def firmware(self, device_id):
        r = self._call("GET", f"/v2.0/cloud/thing/{device_id}/firmware")
        return r if isinstance(r, list) else [r] if r else []

    def upgrade(self, device_id, channel):
        return self._call("POST", f"/v2.0/cloud/thing/{device_id}/firmware/{int(channel)}")


def tuya_category_label(code):
    return TUYA_CATEGORIES.get(code or "", code or "Appareil")


# ─────────────────────────── contrôleur UniFi Network ───────────────────────────

class UniFiController:
    """API locale du contrôleur UniFi Network (console UniFi OS ou application Network classique)."""

    def __init__(self, url, username, password, site="default"):
        self.url = url.rstrip("/")
        if not self.url.startswith("http"):
            self.url = "https://" + self.url
        self.user, self.pw, self.site = username, password, site or "default"
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                  urllib.request.HTTPSHandler(context=_insecure_ctx()),
                                                  urllib.request.HTTPCookieProcessor(self.jar))
        self.unifi_os, self.csrf = None, None

    def _req(self, method, path, body=None):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        req = urllib.request.Request(self.url + path, method=method, headers=headers,
                                     data=json.dumps(body).encode() if body is not None else None)
        with self.opener.open(req, timeout=15) as r:
            self.csrf = r.headers.get("X-CSRF-Token") or r.headers.get("X-Updated-CSRF-Token") or self.csrf
            txt = r.read().decode("utf-8", "ignore")
        return json.loads(txt) if txt else {}

    def login(self):
        creds = {"username": self.user, "password": self.pw, "remember": False}
        try:  # console UniFi OS (UDM, Cloud Key Gen2, UniFi OS Server…)
            self._req("POST", "/api/auth/login", creds)
            self.unifi_os = True
        except urllib.error.HTTPError as e:
            if e.code not in (404, 401, 400):
                raise
            if e.code == 401:
                raise RuntimeError("identifiants UniFi refusés")
            self._req("POST", "/api/login", creds)   # application Network « classique » (port 8443)
            self.unifi_os = False

    def _api(self, path):
        return ("/proxy/network" if self.unifi_os else "") + f"/api/s/{self.site}/{path}"

    def devices(self):
        if self.unifi_os is None:
            self.login()
        return self._req("GET", self._api("stat/device")).get("data", [])

    def command(self, mac, cmd):
        """cmd : restart, set-locate, unset-locate, upgrade, adopt."""
        if self.unifi_os is None:
            self.login()
        return self._req("POST", self._api("cmd/devmgr"), {"cmd": cmd, "mac": mac.lower()})


# ─────────────────────────── Imprimantes 3D ───────────────────────────
# Repris de gbe77at/3Dprinter-mcp (printer_link/discovery), validé sur le vrai réseau :
# Bambu P2S par SSDP, Creality K2 Pro par Moonraker :4408/:7125.

BAMBU_PORTS = (1990, 2021)            # annonces SSDP Bambu (en alternance, toutes les ~5 s)
SSDP_GROUP = "239.255.255.250"
#: codes modèle Bambu ; un code inconnu est gardé tel quel plutôt que deviné
BAMBU_MODELS = {"3DPrinter-X1": "X1", "3DPrinter-X1-Carbon": "X1 Carbon", "C11": "P1P", "C12": "P1S",
                "C13": "X1E", "N1": "A1 mini", "N2S": "A1", "N7": "P2S"}
#: seuls ces ports prouvent une imprimante (un simple :80 prenait des routeurs pour des imprimantes)
PRINTER_PORTS = (7125, 4408, 8883)


def parse_bambu_notify(payload):
    """Annonce SSDP → dict si c'est une imprimante Bambu Lab, sinon None (analyse tolérante)."""
    text = payload.decode("utf-8", "replace")
    lines = text.splitlines()
    if not lines or not lines[0].upper().startswith(("NOTIFY", "HTTP/1.1")):
        return None
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    blob = " ".join(headers.get(k, "") for k in ("nt", "usn", "server", "location"))
    if "bambu" not in blob.lower() and not any(k.endswith(".bambu.com") for k in headers):
        return None

    def h(*names):
        return next((headers[n] for n in names if headers.get(n)), "")
    raw = h("devmodel.bambu.com", "devmodel")
    return {"ip": h("location").replace("http://", "").split(":")[0].strip() or h("host").split(":")[0],
            "serial": h("usn", "devserial.bambu.com"), "raw_model": raw, "model": BAMBU_MODELS.get(raw, raw),
            "name": h("devname.bambu.com", "devname"), "signal": h("devsignal.bambu.com"),
            "connect": h("devconnect.bambu.com").lower(), "bind": h("devbind.bambu.com").lower(),
            "firmware": h("devversion.bambu.com")}


def bambu_sockets():
    """Sockets d'écoute partagés (Bambu Studio / OrcaSlicer écoutent aussi 2021 : ne pas les bloquer)."""
    socks = []
    for port in BAMBU_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        try:
            s.bind(("", port))
            mreq = struct.pack("4sl", socket.inet_aton(SSDP_GROUP), socket.INADDR_ANY)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError:
            s.close()
            continue
        socks.append(s)
    return socks


def _get_json(url, timeout=4):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=timeout) as r:
            if r.status != 200:
                return None
            return json.loads(r.read(400000).decode("utf-8", "ignore"))
    except Exception:
        return None


def parse_moonraker(info, sysinfo=None, cfg=None):
    """Réponses Moonraker → dict (marque devinée prudemment, cinématique, plateau)."""
    res = (info or {}).get("result", info or {})
    if not isinstance(res, dict) or not ("software_version" in res or "hostname" in res or "state" in res):
        return None
    hostname = str(res.get("hostname") or "")
    dist = (((sysinfo or {}).get("result") or {}).get("system_info") or {}).get("distribution") or {}
    distro = str(dist.get("name", ""))
    settings = ((((cfg or {}).get("result") or {}).get("status") or {}).get("configfile") or {}).get("settings") or {}
    kin = str((settings.get("printer") or {}).get("kinematics", ""))
    blob = f"{hostname} {distro}".lower()
    model = None
    m = re.search(r"\b(k[12](?:\s?(?:pro|plus|max|c|se))?)\b", hostname.replace("-", " ").lower())
    if "flsun" in blob:
        brand = "FLSun"
        f = re.search(r"(v|t|s|q|sr|super\s?racer)\s?(\d{3})?\s?(max|pro|plus|s)?\b",
                      hostname.lower().replace("flsun", "").replace("-", " ").strip())
        if f and (f.group(2) or f.group(1).startswith("s")):
            model = (f.group(1).upper() + (f.group(2) or "") + (" " + f.group(3).title() if f.group(3) else "")).strip()
    elif "creality" in blob or m:
        brand = "Creality"
        if m:  # « k2pro » / « k2 pro » → « K2 Pro », « k1c » → « K1C »
            code = m.group(1).replace(" ", "")
            model = code[:2].upper() + {"pro": " Pro", "plus": " Plus", "max": " Max", "c": "C",
                                        "se": " SE"}.get(code[2:], "")
    else:
        brand = "Klipper"
    if brand == "Klipper" and "delta" in kin.lower():
        brand, model = "Klipper (delta)", "delta — FLSun probable"
    return {"brand": brand, "model": model, "hostname": hostname, "klipper": str(res.get("software_version") or ""),
            "state": str(res.get("state") or ""), "distro": distro, "kinematics": kin}


def moonraker_probe(ip, ports=(7125, 4408, 80)):
    """Interroge Moonraker (API Klipper) ; :80 n'est accepté que s'il répond comme Moonraker."""
    for port in ports:
        base = f"http://{ip}:{port}"
        info = _get_json(f"{base}/printer/info")
        if not info:
            continue
        r = parse_moonraker(info, _get_json(f"{base}/machine/system_info"),
                            _get_json(f"{base}/printer/objects/query?configfile"))
        if r:
            r["port"] = port
            return r
    return None
