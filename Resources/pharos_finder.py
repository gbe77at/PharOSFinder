#!/usr/bin/env python3
"""
Pharos Finder — découverte et accès aux équipements TP-Link PharOS (CPE / WBS) sur macOS.

Inspiré de Pharos Control (TP-Link) et QNAP Finder :
  • balayage ARP des réseaux de chaque interface active ;
  • sondage des plages d'usine PharOS (192.168.0.254 par défaut) via un alias IP temporaire ;
  • écoute passive du câble (tcpdump) : ARP, DHCP et trafic TDP (UDP 20002, le port de
    découverte utilisé par Pharos Control) — trouve un équipement même s'il est dans une
    plage IP inconnue ;
  • identification : préfixe MAC TP-Link, page web (titre / « PharOS » / modèle CPE-WBS),
    bannière SSH (port 22, canal de gestion Pharos Control) ;
  • accès : alias automatique pour rendre l'équipement joignable, ouverture de l'interface
    web, session SSH dans Terminal, assistant de changement d'IP avec suivi de la nouvelle
    adresse.

Python 3.8+ standard, aucune dépendance. Lancer avec sudo (alias IP et tcpdump).
Les alias ajoutés sont retirés automatiquement à la fermeture.
"""

import argparse
import atexit
import concurrent.futures as cf
import ipaddress
import json
import os
import platform
import re
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

VERSION = "1.0"
IS_MAC = platform.system() == "Darwin"
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
SUDO_USER = os.environ.get("SUDO_USER")

PHAROS_DEFAULT_IP = "192.168.0.254"
FACTORY_NETS = ["192.168.0.0/24", "192.168.1.0/24"]
PRIORITY_HOSTS = [254, 1, 253, 2, 100, 250]
PHAROS_MODEL_RE = re.compile(r"\b((?:CPE|WBS)\d{3}[A-Z]?)\b")

# Préfixes OUI TP-Link courants (liste non exhaustive ; les autres sont résolus en ligne
# via api.macvendors.com quand Internet est disponible).
TPLINK_OUIS = {
    "00:1d:0f", "00:23:cd", "00:27:19", "00:31:92", "10:27:f5", "14:cc:20", "14:cf:92",
    "18:a6:f7", "18:d6:c7", "1c:3b:f3", "1c:61:b4", "20:23:51", "28:87:ba", "30:68:93",
    "30:b5:c2", "30:de:4b", "34:60:f9", "3c:46:d8", "3c:52:a1", "40:ed:00", "50:3e:aa",
    "50:91:e3", "50:c7:bf", "54:c8:0f", "5c:63:bf", "5c:a6:e6", "5c:e9:31", "60:32:b1",
    "60:a4:b7", "60:e3:27", "64:66:b3", "64:70:02", "6c:5a:b0", "70:4f:57", "74:da:88",
    "78:8c:b5", "84:16:f9", "88:25:93", "8c:90:2d", "90:f6:52", "98:25:4a", "98:da:c4",
    "9c:a2:f4", "a0:f3:c1", "a4:2b:b0", "a8:42:a1", "ac:84:c6", "b0:4e:26", "b0:95:75",
    "b0:be:76", "b4:b0:24", "c0:06:c3", "c0:25:e9", "c0:4a:00", "c4:6e:1f", "c4:e9:84",
    "cc:32:e5", "d4:6e:0e", "d8:07:b6", "e4:c3:2a", "e8:94:f6", "ec:08:6b", "ec:17:2f",
    "f4:ec:38", "f8:1a:67",
}

SKIP_IFACE_PREFIXES = ("lo", "gif", "stf", "utun", "awdl", "llw", "anpi", "ap", "bridge", "vmenet", "docker", "veth")

# ─────────────────────────── état partagé ───────────────────────────

LOCK = threading.RLock()
DEVICES = {}        # id -> device dict
LOG = []            # entrées de journal
JOBS = {}           # nom -> {"label", "started", "proc"?}
ALIASES = []        # [{"iface", "ip", "mask", "keep_reason"}]
VENDOR_CACHE = {}
VENDOR_LOCK = threading.Lock()
TOKEN = secrets.token_urlsafe(16)


def log(msg, level="info"):
    entry = {"t": time.strftime("%H:%M:%S"), "level": level, "msg": msg}
    with LOCK:
        LOG.append(entry)
        del LOG[:-500]
    print(f"[{entry['t']}] {level.upper():5} {msg}", flush=True)


def run(cmd, timeout=15):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0]} introuvable")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "délai dépassé")


def as_user(cmd):
    """Exécute une commande graphique (open, osascript) dans la session de l'utilisateur."""
    if IS_ROOT and SUDO_USER:
        cmd = ["sudo", "-u", SUDO_USER] + cmd
    return run(cmd)


# ─────────────────────────── MAC / fabricant ───────────────────────────

def norm_mac(mac):
    parts = mac.strip().lower().split(":")
    if len(parts) != 6:
        return None
    try:
        return ":".join(f"{int(p, 16):02x}" for p in parts)
    except ValueError:
        return None


def is_local_mac(mac):
    return bool(int(mac.split(":")[0], 16) & 0x02)


def is_multicast_mac(mac):
    return bool(int(mac.split(":")[0], 16) & 0x01)


def vendor_of(mac):
    if not mac:
        return None
    if mac[:8] in TPLINK_OUIS:
        return "TP-Link"
    if is_local_mac(mac):
        return "MAC locale / aléatoire"
    return VENDOR_CACHE.get(mac[:8])


def lookup_vendor_online(mac):
    """Résout le fabricant via api.macvendors.com (1 requête/s max). Silencieux si hors ligne."""
    prefix = mac[:8]
    if prefix in VENDOR_CACHE or prefix in TPLINK_OUIS or is_local_mac(mac):
        return vendor_of(mac)
    with VENDOR_LOCK:
        if prefix in VENDOR_CACHE:
            return VENDOR_CACHE[prefix]
        try:
            req = urllib.request.Request(f"https://api.macvendors.com/{prefix}",
                                         headers={"User-Agent": "PharosFinder"})
            with urllib.request.urlopen(req, timeout=3) as r:
                name = r.read(200).decode("utf-8", "ignore").strip()
        except Exception:
            name = None
        time.sleep(1.1)
        if name and ("tp-link" in name.lower() or "tp link" in name.lower()):
            name = "TP-Link"
        VENDOR_CACHE[prefix] = name
        return name


# ─────────────────────────── interfaces ───────────────────────────

_HW_CACHE = {"t": 0.0, "v": {}}


def hardware_ports():
    """Associe device -> nom lisible (« USB 10/100/1000 LAN », « Wi-Fi »…). Cache 30 s."""
    if not IS_MAC:
        return {}
    if time.time() - _HW_CACHE["t"] < 30:
        return _HW_CACHE["v"]
    out = run(["networksetup", "-listallhardwareports"]).stdout
    names, port = {}, None
    for line in out.splitlines():
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and port:
            names[line.split(":", 1)[1].strip()] = port
            port = None
    _HW_CACHE.update(t=time.time(), v=names)
    return names


def parse_ifconfig(text):
    ifaces, cur = [], None
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+): flags=", line)
        if m:
            cur = {"name": m.group(1), "mac": None, "ipv4": [], "status": None}
            ifaces.append(cur)
            continue
        if cur is None:
            continue
        s = line.strip()
        if s.startswith("ether "):
            cur["mac"] = norm_mac(s.split()[1])
        elif s.startswith("inet "):
            m = re.match(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)\s+(?:netmask|Mask:)\s*(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)", s)
            if m:
                ip, mask = m.group(1), m.group(2)
                if mask.startswith("0x"):
                    mask = str(ipaddress.IPv4Address(int(mask, 16)))
                prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                cur["ipv4"].append({"ip": ip, "mask": mask, "prefix": prefix})
        elif s.startswith("status:"):
            cur["status"] = s.split(":", 1)[1].strip()
    return ifaces


def list_interfaces():
    ports = hardware_ports()
    res = []
    for i in parse_ifconfig(run(["ifconfig"]).stdout):
        if i["name"].startswith(SKIP_IFACE_PREFIXES) or not i["mac"]:
            continue
        i["label"] = ports.get(i["name"], i["name"])
        i["active"] = (i["status"] == "active") if i["status"] is not None else bool(i["ipv4"])
        with LOCK:
            i["aliases"] = [a["ip"] for a in ALIASES if a["iface"] == i["name"]]
        res.append(i)
    res.sort(key=lambda x: (not x["active"], not x["ipv4"], x["name"]))
    return res


def get_iface(name):
    for i in list_interfaces():
        if i["name"] == name:
            return i
    return None


def iface_networks(iface):
    nets = []
    for a in iface["ipv4"]:
        nets.append(ipaddress.ip_network(f"{a['ip']}/{a['prefix']}", strict=False))
    return nets


def all_local_ips():
    ips = set()
    for i in list_interfaces():
        ips.update(a["ip"] for a in i["ipv4"])
    return ips


# ─────────────────────────── alias IP ───────────────────────────

def add_alias(iface, ip, mask, reason=""):
    if not IS_ROOT:
        raise RuntimeError("droits admin requis pour ajouter un alias (relancer avec sudo)")
    r = run(["ifconfig", iface, "alias", ip, mask]) if IS_MAC else \
        run(["ip", "addr", "add", f"{ip}/{ipaddress.IPv4Network('0.0.0.0/' + mask).prefixlen}", "dev", iface])
    if r.returncode != 0:
        raise RuntimeError(f"alias {ip} sur {iface} refusé : {r.stderr.strip()}")
    with LOCK:
        ALIASES.append({"iface": iface, "ip": ip, "mask": mask, "keep_reason": reason})
    log(f"Alias temporaire {ip}/{mask} ajouté sur {iface}")
    time.sleep(0.8)


def remove_alias(iface, ip):
    with LOCK:
        entry = next((a for a in ALIASES if a["iface"] == iface and a["ip"] == ip), None)
        if entry:
            ALIASES.remove(entry)
    if IS_MAC:
        run(["ifconfig", iface, "-alias", ip])
    else:
        mask = entry["mask"] if entry else "255.255.255.0"
        run(["ip", "addr", "del", f"{ip}/{ipaddress.IPv4Network('0.0.0.0/' + mask).prefixlen}", "dev", iface])
    log(f"Alias {ip} retiré de {iface}")


def cleanup_aliases():
    with LOCK:
        pending = list(ALIASES)
    for a in pending:
        try:
            remove_alias(a["iface"], a["ip"])
        except Exception:
            pass


def pick_alias_ip(net, avoid=()):
    avoid = set(avoid) | all_local_ips()
    with LOCK:
        avoid |= {d["ip"] for d in DEVICES.values() if d["ip"]}
    top = int(net.broadcast_address)
    for off in range(4, 60):
        cand = str(ipaddress.IPv4Address(top - off))
        if cand not in avoid and ipaddress.IPv4Address(cand) in net:
            return cand
    raise RuntimeError(f"pas d'adresse libre trouvée pour l'alias dans {net}")


def ensure_reachable(ip, iface, prefix=24):
    """Ajoute un alias dans le sous-réseau de `ip` si aucune interface n'y est déjà."""
    target = ipaddress.IPv4Address(ip)
    for i in list_interfaces():
        for n in iface_networks(i):
            if target in n and not ip.startswith("169.254."):
                return None
    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    alias = pick_alias_ip(net, avoid={ip})
    add_alias(iface, alias, str(net.netmask), reason=f"accès à {ip}")
    return alias


# ─────────────────────────── sondes réseau ───────────────────────────

def ping(ip, timeout_ms=500):
    cmd = ["ping", "-c", "1"]
    cmd += ["-W", str(timeout_ms)] if IS_MAC else ["-W", "1"]
    cmd.append(str(ip))
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=3).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def sweep(hosts, workers=64):
    alive = []
    with cf.ThreadPoolExecutor(workers) as ex:
        for ip, ok in zip(hosts, ex.map(ping, hosts)):
            if ok:
                alive.append(str(ip))
    return alive


ARP_RE = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]{11,17})(?: \[\w+\])? on (\S+)")


def arp_table():
    out = run(["arp", "-an"]).stdout
    entries = []
    for m in ARP_RE.finditer(out):
        mac = norm_mac(m.group(2))
        if not mac or mac == "ff:ff:ff:ff:ff:ff" or is_multicast_mac(mac):
            continue
        entries.append({"ip": m.group(1), "mac": mac, "iface": m.group(3)})
    return entries


def tcp_open(ip, port, timeout=0.8):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def ssh_banner(ip):
    try:
        with socket.create_connection((ip, 22), timeout=2) as s:
            s.settimeout(2)
            return s.recv(256).decode("utf-8", "ignore").strip() or None
    except OSError:
        return None


def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (AttributeError, ValueError):
        pass
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")  # vieux firmwares PharOS
    except ssl.SSLError:
        pass
    return ctx


def http_probe(ip, open_ports):
    # ProxyHandler({}) : on parle directement à l'équipement, jamais via un proxy système.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=_ssl_ctx()))
    tries = []
    if 443 in open_ports:
        tries.append(f"https://{ip}/")
    if 80 in open_ports:
        tries.append(f"http://{ip}/")
    for url in tries:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 PharosFinder"})
            with opener.open(req, timeout=5) as r:
                body = r.read(300_000).decode("utf-8", "ignore")
                final = r.geturl()
                server = r.headers.get("Server")
        except Exception:
            continue
        t = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
        title = re.sub(r"\s+", " ", t.group(1)).strip()[:120] if t else None
        low = body.lower()
        model = PHAROS_MODEL_RE.search(body)
        return {
            "web": final or url,
            "title": title,
            "server": server,
            "pharos_hint": "pharos" in low,
            "tplink_hint": "tp-link" in low or "tplink" in low or "tp_link" in low,
            "model": model.group(1) if model else None,
        }
    return None


# ─────────────────────────── modèle d'équipement ───────────────────────────

def _new_device(key, mac, ip):
    return {"id": key, "mac": mac, "ip": ip, "ips": [], "vendor": None, "kind": "other",
            "iface": None, "model": None, "title": None, "server": None, "ports": [],
            "ssh": None, "sources": [], "tdp": False, "pharos_hint": False,
            "tplink_hint": False, "web": None, "reachable": None, "last_seen": None,
            "fingerprinted": False}


def classify(d):
    text = " ".join(filter(None, [d.get("title"), d.get("model"), d.get("server")])).lower()
    if d.get("pharos_hint") or "pharos" in text or (d.get("model") and PHAROS_MODEL_RE.match(d["model"])):
        d["kind"] = "pharos"
    elif d.get("vendor") == "TP-Link" or d.get("tplink_hint") or d.get("tdp") or "tp-link" in text:
        d["kind"] = "tplink"
    else:
        d["kind"] = "other"


def upsert(mac=None, ip=None, source=None, **fields):
    if ip and (ip.startswith("0.") or ip == "255.255.255.255"):
        ip = None
    if not mac and not ip:
        return None
    with LOCK:
        key = mac or f"ip:{ip}"
        d = DEVICES.get(key)
        if mac and ip and f"ip:{ip}" in DEVICES:  # fusion d'un équipement vu sans MAC
            old = DEVICES.pop(f"ip:{ip}")
            if d is None:
                d = old
                d["id"], d["mac"] = key, mac
                DEVICES[key] = d
            else:
                for k, v in old.items():
                    if d.get(k) in (None, [], False) and v not in (None, [], False):
                        d[k] = v
        if d is None:
            d = _new_device(key, mac, ip)
            DEVICES[key] = d
        if ip:
            if ip not in d["ips"]:
                d["ips"].append(ip)
            if not ip.startswith("169.254.") or not d["ip"]:
                d["ip"] = ip
        if source and source not in d["sources"]:
            d["sources"].append(source)
        for k, v in fields.items():
            if k in ("tdp", "pharos_hint", "tplink_hint"):
                d[k] = d[k] or bool(v)
            elif v is not None:
                d[k] = v
        if mac and not d["vendor"]:
            d["vendor"] = vendor_of(mac)
        d["last_seen"] = time.strftime("%H:%M:%S")
        classify(d)
        return d


def fingerprint(dev_id):
    with LOCK:
        d = DEVICES.get(dev_id)
        if not d or not d["ip"]:
            return
        ip, mac = d["ip"], d["mac"]
    open_ports = [p for p in (22, 80, 443) if tcp_open(ip, p)]
    info = {"ports": open_ports, "reachable": bool(open_ports) or ping(ip, 800), "fingerprinted": True}
    if 22 in open_ports:
        info["ssh"] = ssh_banner(ip)
    web = http_probe(ip, open_ports) if (80 in open_ports or 443 in open_ports) else None
    if web:
        info.update(web)
    if mac:
        v = vendor_of(mac) or lookup_vendor_online(mac)
        if v:
            info["vendor"] = v
    d = upsert(mac=mac, ip=ip, **info)
    if d:
        label = {"pharos": "PharOS", "tplink": "TP-Link"}.get(d["kind"], "équipement")
        extra = f" — {d['model']}" if d.get("model") else (f" — « {d['title']} »" if d.get("title") else "")
        log(f"{label} {ip} ({mac or 'MAC ?'}){extra} · ports {open_ports or 'aucun'}",
            "ok" if d["kind"] == "pharos" else "info")


def fingerprint_many(ids):
    with cf.ThreadPoolExecutor(8) as ex:
        list(ex.map(fingerprint, ids))


# ─────────────────────────── tâches ───────────────────────────

def start_job(name, label, fn, *args):
    with LOCK:
        if name in JOBS:
            raise RuntimeError(f"« {JOBS[name]['label']} » est déjà en cours")
        JOBS[name] = {"label": label, "started": time.time(), "proc": None}

    def wrapper():
        try:
            fn(*args)
        except Exception as e:  # noqa: BLE001
            log(f"{label} : {e}", "error")
        finally:
            with LOCK:
                JOBS.pop(name, None)

    threading.Thread(target=wrapper, daemon=True).start()


def job_scan(iface_name, factory, full, extra):
    iface = get_iface(iface_name)
    if not iface:
        raise RuntimeError(f"interface {iface_name} introuvable")
    if not iface["active"]:
        log(f"{iface_name} ({iface['label']}) n'a pas de lien actif — câble branché ?", "warn")
    local_ips = {a["ip"] for a in iface["ipv4"]}
    plans = []
    for n in iface_networks(iface):
        if n.network_address.is_link_local:
            log(f"{iface_name} n'a qu'une IP auto-assignée (169.254.x) : pas de DHCP sur ce câble. "
                "Utilise les plages d'usine ou l'écoute passive.", "warn")
            continue
        if n.num_addresses > 1024:
            own = next(a["ip"] for a in iface["ipv4"] if ipaddress.IPv4Address(a["ip"]) in n)
            log(f"Réseau {n} trop grand : balayage limité au /24 autour de {own}")
            n = ipaddress.ip_network(f"{own}/24", strict=False)
        plans.append((n, False))
    if factory:
        for spec in FACTORY_NETS + extra:
            try:
                n = ipaddress.ip_network(spec, strict=False)
            except ValueError:
                log(f"Plage ignorée (invalide) : {spec}", "warn")
                continue
            if n.num_addresses > 1024:
                log(f"Plage {n} trop grande, ignorée (max /22)", "warn")
                continue
            if not any(n.overlaps(p) for p, _ in plans):
                plans.append((n, True))
    if not plans:
        log("Rien à balayer sur cette interface.", "warn")
        return

    found_ids = []
    for net, needs_alias in plans:
        alias = None
        if needs_alias:
            if not IS_ROOT:
                log(f"Plage {net} sautée : alias impossible sans sudo", "warn")
                continue
            alias = pick_alias_ip(net)
            add_alias(iface_name, alias, str(net.netmask), reason=f"sondage {net}")
        hosts = list(net.hosts())
        if needs_alias and not full:
            base = int(net.network_address)
            hosts = [ipaddress.IPv4Address(base + h) for h in PRIORITY_HOSTS
                     if ipaddress.IPv4Address(base + h) in net]
            log(f"Sondage rapide de {net} (.{', .'.join(str(h) for h in PRIORITY_HOSTS)}) depuis {alias}")
        else:
            log(f"Balayage de {net} ({len(hosts)} adresses) sur {iface_name}…")
        alive = set(sweep([h for h in hosts if str(h) not in local_ips and str(h) != alias]))
        # L'ARP se résout même si l'équipement filtre l'ICMP : on lit la table.
        hits = 0
        for e in arp_table():
            if ipaddress.IPv4Address(e["ip"]) in net and e["ip"] not in local_ips and e["ip"] != alias:
                d = upsert(mac=e["mac"], ip=e["ip"], source="balayage", iface=e["iface"])
                if d:
                    found_ids.append(d["id"])
                    hits += 1
        for ip in alive:  # répond au ping mais absent de l'ARP (rare, routé)
            if not any(DEVICES.get(i, {}).get("ip") == ip for i in found_ids):
                d = upsert(ip=ip, source="balayage", iface=iface_name)
                found_ids.append(d["id"])
                hits += 1
        log(f"{net} : {hits} équipement(s)", "ok" if hits else "info")
        if alias:
            if hits:
                with LOCK:
                    for a in ALIASES:
                        if a["ip"] == alias:
                            a["keep_reason"] = f"accès à {net}"
                log(f"Alias {alias} gardé pour accéder à {net} (retiré à la fermeture)")
            else:
                remove_alias(iface_name, alias)
    if found_ids:
        log(f"Identification de {len(set(found_ids))} équipement(s)…")
        fingerprint_many(list(dict.fromkeys(found_ids)))
    log("Recherche terminée.", "ok")


TCPDUMP_HEAD = re.compile(r"^\S+ ([0-9a-f:]{17}) > (\S+), ethertype (\S+) \(0x[0-9a-f]+\), length \d+: (.*)$")
ARP_SENDER = re.compile(r"(?:Request|Probe|Announcement) who-has (\S+?)(?: \([^)]*\))? tell (\S+?)(?:,|$)")
ARP_REPLY = re.compile(r"Reply (\S+) is-at ([0-9a-f:]{17})")
IP_SRC = re.compile(r"^(\d+\.\d+\.\d+\.\d+)(?:\.(\d+))? > (\d+\.\d+\.\d+\.\d+)(?:\.(\d+))?")


def parse_tcpdump_line(line, self_mac=None):
    """Retourne (mac, ip|None, tdp:bool) ou None."""
    m = TCPDUMP_HEAD.match(line.strip())
    if not m:
        return None
    src, etype, rest = m.group(1), m.group(3), m.group(4)
    if src == self_mac or is_multicast_mac(src):
        return None
    ip, tdp = None, False
    if etype == "ARP":
        r = ARP_REPLY.search(rest)
        if r:
            ip = r.group(1)
        else:
            s = ARP_SENDER.search(rest)
            if s:
                ip = s.group(2) if s.group(2) != "0.0.0.0" else None
    elif etype == "IPv4":
        s = IP_SRC.match(rest)
        if s:
            ip = s.group(1)
            ports = {s.group(2), s.group(4)}
            tdp = "20002" in ports or "20001" in ports
    if ip in ("0.0.0.0", "255.255.255.255"):
        ip = None
    return src, ip, tdp


def job_listen(iface_name, seconds):
    if not IS_ROOT:
        raise RuntimeError("l'écoute passive nécessite sudo")
    iface = get_iface(iface_name)
    if not iface:
        raise RuntimeError(f"interface {iface_name} introuvable")
    cmd = ["tcpdump", "-i", iface_name, "-n", "-e", "-l"]
    if iface["mac"]:
        cmd += ["not", "ether", "src", iface["mac"]]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    with LOCK:
        JOBS["listen"]["proc"] = proc
    log(f"Écoute passive sur {iface_name} pendant {seconds} s — débranche/rebranche l'alimentation "
        "du Pharos maintenant pour capter ses annonces.", "ok")
    seen, count = {}, [0]

    def reader():
        for line in proc.stdout:
            count[0] += 1
            p = parse_tcpdump_line(line, iface["mac"])
            if not p:
                continue
            mac, ip, tdp = p
            first = (mac, ip) not in seen
            seen[(mac, ip)] = True
            d = upsert(mac=mac, ip=ip, source="écoute", iface=iface_name, tdp=tdp or None)
            if first:
                note = " · trafic TDP (port 20002)" if tdp else ""
                log(f"Vu {mac} ({d['vendor'] or 'fabricant ?'}) → {ip or 'sans IP'}{note}",
                    "ok" if d["kind"] != "other" else "info")

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    deadline = time.time() + seconds
    while time.time() < deadline and proc.poll() is None:
        time.sleep(0.3)
    if proc.poll() is None:
        proc.terminate()
    t.join(timeout=2)
    macs = {m for (m, _) in seen}
    log(f"Écoute terminée : {count[0]} trame(s), {len(macs)} émetteur(s) distinct(s).", "ok")
    if count[0] == 0:
        log("Aucune trame reçue : lien inactif, mauvais câble, ou port isolé/VLAN différent.", "warn")
    with LOCK:
        ids = [d["id"] for d in DEVICES.values()
               if d["mac"] in macs and d["ip"] and not d["ip"].startswith("169.254.")]
    reachable = []
    for i in ids:
        ip = DEVICES[i]["ip"]
        if any(ipaddress.IPv4Address(ip) in n for n in iface_networks(get_iface(iface_name))):
            reachable.append(i)
    if reachable:
        fingerprint_many(reachable)
    others = len(ids) - len(reachable)
    if others:
        log(f"{others} équipement(s) hors de ta plage IP : sélectionne-les puis « Rendre joignable ».")


def job_reach(dev_id, iface_name, prefix):
    with LOCK:
        d = DEVICES.get(dev_id)
        ip = d["ip"] if d else None
    if not ip:
        raise RuntimeError("équipement sans IP connue — lance une écoute passive")
    iface = iface_name or (d.get("iface") if d else None)
    if not iface:
        raise RuntimeError("choisis l'interface reliée à l'équipement")
    alias = ensure_reachable(ip, iface, prefix)
    if alias is None:
        log(f"{ip} est déjà dans une plage de tes interfaces.")
    fingerprint(dev_id)
    with LOCK:
        ok = DEVICES[dev_id]["reachable"]
    log(f"{ip} {'joignable' if ok else 'ne répond toujours pas'}", "ok" if ok else "warn")


def job_watch(new_ip, prefix, iface_name, timeout=240):
    ipaddress.IPv4Address(new_ip)
    if iface_name:
        ensure_reachable(new_ip, iface_name, prefix)
    log(f"Suivi de {new_ip} : j'attends que l'équipement revienne (max {timeout // 60} min)…")
    start = time.time()
    while time.time() - start < timeout:
        if JOBS.get("watch", {}).get("stop"):
            log("Suivi interrompu.", "warn")
            return
        if tcp_open(new_ip, 443, 1) or tcp_open(new_ip, 80, 1) or ping(new_ip, 800):
            mac = next((e["mac"] for e in arp_table() if e["ip"] == new_ip), None)
            d = upsert(mac=mac, ip=new_ip, source="suivi", iface=iface_name)
            fingerprint(d["id"])
            log(f"{new_ip} répond après {int(time.time() - start)} s. Interface web : https://{new_ip}/", "ok")
            return
        time.sleep(2)
    log(f"{new_ip} ne répond pas après {timeout} s. Vérifie le masque/la passerelle saisis, "
        "ou relance une écoute passive.", "error")


# ─────────────────────────── actions utilisateur ───────────────────────────

def open_url(url):
    r = as_user(["open", url]) if IS_MAC else as_user(["xdg-open", url])
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "ouverture impossible")


def open_ssh(ip, user):
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", user or ""):
        raise RuntimeError("nom d'utilisateur invalide")
    ipaddress.IPv4Address(ip)
    ssh = (f"ssh -o StrictHostKeyChecking=accept-new "
           f"-o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 "
           f"-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa {user}@{ip}")
    if not IS_MAC:
        raise RuntimeError(f"ouvre un terminal et lance : {ssh}")
    script = f'tell application "Terminal"\nactivate\ndo script "{ssh}"\nend tell'
    r = as_user(["osascript", "-e", script])
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "Terminal inaccessible")


def snapshot():
    ifaces = list_interfaces()
    nets = [(i["name"], n) for i in ifaces for n in iface_networks(i) if not n.network_address.is_link_local]
    with LOCK:
        devs = []
        for d in DEVICES.values():
            c = dict(d)
            c["in_range"] = bool(d["ip"]) and not d["ip"].startswith("169.254.") and \
                any(ipaddress.IPv4Address(d["ip"]) in n for _, n in nets)
            devs.append(c)
        order = {"pharos": 0, "tplink": 1, "other": 2}
        devs.sort(key=lambda x: (order[x["kind"]], tuple(int(p) for p in (x["ip"] or "255.255.255.255").split("."))))
        return {
            "version": VERSION, "root": IS_ROOT, "mac_os": IS_MAC,
            "interfaces": ifaces, "devices": devs, "log": LOG[-200:],
            "jobs": {k: {"label": v["label"], "elapsed": int(time.time() - v["started"])} for k, v in JOBS.items()},
            "aliases": list(ALIASES),
        }


# ─────────────────────────── serveur HTTP local ───────────────────────────

class Handler(BaseHTTPRequestHandler):
    server_version = "PharosFinder/" + VERSION

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self):
        return secrets.compare_digest(self.headers.get("X-Token", ""), TOKEN)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            if parse_qs(u.query).get("t", [""])[0] != TOKEN:
                return self._send(403, b"Lien invalide : utilise l'URL affichee au lancement.", "text/plain")
            return self._send(200, UI_HTML.encode(), "text/html")
        if u.path == "/api/state":
            if not self._authorized():
                return self._send(403, {"error": "jeton invalide"})
            return self._send(200, snapshot())
        self._send(404, {"error": "introuvable"})

    def do_POST(self):
        if not self._authorized():
            return self._send(403, {"error": "jeton invalide"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
            res = self.dispatch(urlparse(self.path).path, body)
            self._send(200, res or {"ok": True})
        except Exception as e:  # noqa: BLE001
            self._send(400, {"error": str(e)})

    def dispatch(self, path, b):
        if path == "/api/scan":
            extra = [s.strip() for s in re.split(r"[,\s]+", b.get("extra", "")) if s.strip()]
            start_job("scan", "Recherche", job_scan, b["iface"], bool(b.get("factory")), bool(b.get("full")), extra)
        elif path == "/api/listen":
            secs = max(10, min(int(b.get("seconds", 60)), 600))
            start_job("listen", "Écoute passive", job_listen, b["iface"], secs)
        elif path == "/api/stop":
            with LOCK:
                for j in JOBS.values():
                    j["stop"] = True
                    if j.get("proc") and j["proc"].poll() is None:
                        j["proc"].terminate()
        elif path == "/api/reach":
            start_job("reach", "Rendre joignable", job_reach, b["id"], b.get("iface"), int(b.get("prefix", 24)))
        elif path == "/api/refresh":
            start_job("refresh", "Identification", fingerprint, b["id"])
        elif path == "/api/watch":
            start_job("watch", "Suivi nouvelle IP", job_watch, b["ip"], int(b.get("prefix", 24)), b.get("iface"))
        elif path == "/api/open":
            ip = str(ipaddress.IPv4Address(b["ip"]))
            scheme = "http" if b.get("scheme") == "http" else "https"
            open_url(f"{scheme}://{ip}/")
        elif path == "/api/ssh":
            open_ssh(b["ip"], b.get("user", "admin"))
        elif path == "/api/alias/remove":
            remove_alias(b["iface"], b["ip"])
        elif path == "/api/quit":
            def _bye():
                time.sleep(0.2)
                cleanup_aliases()
                os._exit(0)
            threading.Thread(target=_bye, daemon=True).start()
        elif path == "/api/clear":
            with LOCK:
                DEVICES.clear()
            log("Liste vidée.")
        else:
            raise RuntimeError("action inconnue")
        return {"ok": True}


def main():
    ap = argparse.ArgumentParser(description="Pharos Finder — découverte des équipements TP-Link PharOS")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--token", help="jeton fixe (utilisé par l'app macOS)")
    ap.add_argument("--parent-pid", type=int, help="s'arrête quand ce processus disparaît")
    args = ap.parse_args()

    global TOKEN
    if args.token:
        TOKEN = args.token
    if args.parent_pid:
        def _watch_parent(pid):
            while True:
                time.sleep(2)
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    log("Application fermée : arrêt du moteur.")
                    cleanup_aliases()
                    os._exit(0)
                except PermissionError:
                    pass
        threading.Thread(target=_watch_parent, args=(args.parent_pid,), daemon=True).start()

    if not IS_MAC:
        print("⚠️  Conçu pour macOS ; fonctionnement partiel ailleurs.")
    if not IS_ROOT:
        print("⚠️  Lancé sans sudo : balayage OK, mais pas d'alias IP ni d'écoute passive.")

    atexit.register(cleanup_aliases)

    def _sig(*_):
        cleanup_aliases()
        os._exit(0)

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, _sig)  # fenêtre Terminal fermée

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{args.port}/?t={TOKEN}"
    print(f"\n  Pharos Finder {VERSION}\n  Interface : {url}\n  Ctrl+C pour quitter (les alias ajoutés seront retirés).\n")
    log("Pharos Finder prêt. Choisis l'interface reliée au Pharos puis « Rechercher ».", "ok")
    if not args.no_browser:
        threading.Timer(0.6, lambda: open_url(url) if IS_MAC else None).start()
    try:
        srv.serve_forever()
    finally:
        cleanup_aliases()


UI_HTML = r"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pharos Finder</title>
<style>
:root{
  --bg:#f3f4f6; --panel:#ffffff; --panel2:#f8fafc; --line:#e2e5ea; --text:#15191f; --muted:#6b7280;
  --accent:#0a6ecf; --accent-ink:#fff; --ok:#15803d; --warn:#b45309; --err:#b91c1c;
  --pharos:#0a6ecf; --tplink:#0d9488; --other:#9ca3af; --sel:#e8f1fb; --mono:ui-monospace,SFMono-Regular,Menlo,monospace;
}
@media (prefers-color-scheme: dark){:root{
  --bg:#15171b; --panel:#1d2025; --panel2:#23272d; --line:#30353d; --text:#e8eaed; --muted:#9aa1ab;
  --accent:#3b93f0; --sel:#1f3350; --ok:#4ade80; --warn:#fbbf24; --err:#f87171; --pharos:#3b93f0; --tplink:#2dd4bf;
}}
*{box-sizing:border-box}
body{margin:0;font:13px/1.4 -apple-system,BlinkMacSystemFont,"SF Pro Text","Helvetica Neue",sans-serif;background:var(--bg);color:var(--text);height:100vh;display:flex;flex-direction:column}
header{display:flex;align-items:center;gap:12px;padding:10px 16px;background:var(--panel);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:10px;font-weight:650;font-size:15px;letter-spacing:-.01em}
.brand svg{width:26px;height:26px}
.brand small{font-weight:400;color:var(--muted);font-size:12px}
.spacer{flex:1}
.pill{font-size:11px;padding:2px 8px;border-radius:99px;border:1px solid var(--line);color:var(--muted)}
.pill.warn{color:var(--warn);border-color:currentColor}
.toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:10px;padding:10px 16px;background:var(--panel2);border-bottom:1px solid var(--line)}
select,input[type=text],input[type=number]{font:inherit;color:var(--text);background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:5px 8px}
select{min-width:260px}
label.chk{display:flex;align-items:center;gap:5px;color:var(--text);white-space:nowrap}
button{font:inherit;border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:6px;padding:5px 12px;cursor:pointer;white-space:nowrap}
button:hover{border-color:var(--accent)}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink);font-weight:600}
button.danger{color:var(--err)}
button:disabled{opacity:.45;cursor:default}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:6px;overflow:hidden}
.seg button{border:0;border-radius:0;border-right:1px solid var(--line)}
.seg button:last-child{border-right:0}
.seg button.on{background:var(--sel);color:var(--accent);font-weight:600}
main{flex:1;display:flex;min-height:0}
.list{flex:1;overflow:auto;min-width:0}
table{width:100%;border-collapse:collapse}
th{position:sticky;top:0;background:var(--panel2);text-align:left;font-weight:600;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.04em;padding:7px 10px;border-bottom:1px solid var(--line)}
td{padding:7px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
tr.row{cursor:pointer;background:var(--panel)}
tr.row:hover{background:var(--panel2)}
tr.row.sel{background:var(--sel)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;background:var(--other)}
.dot.pharos{background:var(--pharos)} .dot.tplink{background:var(--tplink)}
.mono{font-family:var(--mono);font-size:12px}
.tag{display:inline-block;font-size:10.5px;padding:1px 6px;border-radius:4px;margin-right:3px;border:1px solid var(--line);color:var(--muted)}
.tag.out{color:var(--warn);border-color:currentColor}
.tag.tdp{color:var(--tplink);border-color:currentColor}
.empty{padding:60px 20px;text-align:center;color:var(--muted)}
.empty b{display:block;color:var(--text);font-size:15px;margin-bottom:6px}
aside{width:360px;flex:none;border-left:1px solid var(--line);background:var(--panel);overflow:auto;padding:16px}
aside h2{margin:0 0 2px;font-size:16px}
aside .sub{color:var(--muted);margin-bottom:14px}
dl{display:grid;grid-template-columns:96px 1fr;gap:5px 10px;margin:0 0 16px}
dt{color:var(--muted)} dd{margin:0;word-break:break-all}
.actions{display:grid;gap:7px;margin-bottom:16px}
.actions button{text-align:left;padding:7px 12px}
.card{border:1px solid var(--line);border-radius:8px;padding:12px;margin-bottom:14px;background:var(--panel2)}
.card h3{margin:0 0 8px;font-size:13px}
.card ol{margin:0 0 10px;padding-left:18px;color:var(--muted)}
.card ol li{margin-bottom:3px}
.row2{display:flex;gap:6px;margin-bottom:6px}
.row2 input{flex:1;min-width:0}
.hint{color:var(--muted);font-size:12px}
footer{height:170px;flex:none;border-top:1px solid var(--line);background:var(--panel);display:flex;flex-direction:column}
footer .bar{display:flex;align-items:center;gap:10px;padding:5px 16px;border-bottom:1px solid var(--line);color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.04em}
#log{flex:1;overflow:auto;padding:6px 16px;font-family:var(--mono);font-size:11.5px}
#log div{padding:1px 0}
#log .t{color:var(--muted);margin-right:8px}
#log .ok{color:var(--ok)} #log .warn{color:var(--warn)} #log .error{color:var(--err)}
.job{display:inline-flex;align-items:center;gap:6px;color:var(--accent);text-transform:none;letter-spacing:0;font-size:12px}
.spin{width:10px;height:10px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:s .8s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}
.aliases{display:flex;gap:6px;flex-wrap:wrap}
.alias{font-family:var(--mono);font-size:11px;border:1px solid var(--line);border-radius:4px;padding:1px 4px 1px 6px;text-transform:none;letter-spacing:0;color:var(--text)}
.alias button{border:0;padding:0 4px;background:none;color:var(--muted)}
#toast{position:fixed;bottom:190px;left:50%;transform:translateX(-50%);background:var(--err);color:#fff;padding:8px 14px;border-radius:6px;display:none;max-width:80vw}
@media (max-width:900px){aside{width:300px}select{min-width:180px}}
</style>
</head>
<body>
<header>
  <div class="brand">
    <svg viewBox="0 0 32 32" fill="none" aria-hidden="true">
      <path d="M16 6v20" stroke="var(--accent)" stroke-width="2.4" stroke-linecap="round"/>
      <path d="M10.5 10.5a8 8 0 0 0 0 11M21.5 10.5a8 8 0 0 1 0 11" stroke="var(--accent)" stroke-width="2" stroke-linecap="round"/>
      <path d="M6.5 6.5a13.5 13.5 0 0 0 0 19M25.5 6.5a13.5 13.5 0 0 1 0 19" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" opacity=".45"/>
      <circle cx="16" cy="16" r="2.6" fill="var(--accent)"/>
    </svg>
    Pharos Finder <small id="ver"></small>
  </div>
  <div class="spacer"></div>
  <span class="pill" id="rootPill"></span>
</header>

<div class="toolbar">
  <select id="iface" title="Interface reliée au Pharos"></select>
  <label class="chk" title="Ajoute un alias temporaire pour sonder 192.168.0.x (IP d'usine PharOS : .254) et 192.168.1.x"><input type="checkbox" id="factory" checked> Plages d'usine</label>
  <label class="chk" title="Balaye les 254 adresses des plages d'usine au lieu des seules adresses probables"><input type="checkbox" id="full"> Balayage complet</label>
  <input type="text" id="extra" placeholder="Autres plages : 10.0.0.0/24…" style="width:190px">
  <button class="primary" id="btnScan">Rechercher</button>
  <button id="btnListen" title="Capture le trafic du câble (ARP, DHCP, TDP 20002) : trouve un équipement dans n'importe quelle plage">Écoute passive</button>
  <input type="number" id="secs" value="60" min="10" max="600" style="width:62px" title="Durée d'écoute (s)"> s
  <button class="danger" id="btnStop" disabled>Stop</button>
  <div class="spacer"></div>
  <div class="seg" id="filter">
    <button data-f="pharos">PharOS</button><button data-f="tplink" class="on">TP-Link</button><button data-f="all">Tous</button>
  </div>
</div>

<main>
  <div class="list">
    <table>
      <thead><tr><th>Équipement</th><th>Adresse IP</th><th>MAC</th><th>Fabricant</th><th>Interface</th><th>Services</th><th>Vu</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
    <div class="empty" id="empty"><b>Aucun équipement pour l'instant</b>Choisis l'interface reliée au Pharos, puis <em>Rechercher</em>.<br>S'il est dans une plage inconnue : <em>Écoute passive</em> et redémarre-le pendant l'écoute.</div>
  </div>
  <aside id="detail"><div class="empty" style="padding:40px 0"><b>Sélectionne un équipement</b>pour l'ouvrir, t'y connecter ou changer son IP.</div></aside>
</main>

<footer>
  <div class="bar"><span>Journal</span><span id="jobs"></span><div class="spacer"></div><div class="aliases" id="aliases"></div></div>
  <div id="log"></div>
</footer>
<div id="toast"></div>

<script>
const TOKEN = new URLSearchParams(location.search).get('t');
let S = null, selected = null, filter = 'tplink', ifaceTouched = false, logLen = 0;
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

async function api(path, body){
  const r = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json','X-Token':TOKEN}, body:JSON.stringify(body||{})});
  const j = await r.json().catch(()=>({}));
  if(!r.ok){ toast(j.error || 'Erreur'); throw new Error(j.error); }
  refresh(); return j;
}
function toast(msg){ const t=$('toast'); t.textContent=msg; t.style.display='block'; clearTimeout(t._h); t._h=setTimeout(()=>t.style.display='none',4500); }

async function refresh(){
  try{
    const r = await fetch('/api/state', {headers:{'X-Token':TOKEN}});
    if(!r.ok) return;
    S = await r.json(); render();
  }catch(e){ $('jobs').innerHTML = '<span style="color:var(--err)">Serveur arrêté</span>'; }
}

function render(){
  $('ver').textContent = 'v' + S.version;
  const rp = $('rootPill');
  rp.textContent = S.root ? 'Mode admin' : 'Sans sudo : alias et écoute indisponibles';
  rp.className = 'pill' + (S.root ? '' : ' warn');

  // interfaces
  const sel = $('iface'), cur = sel.value;
  sel.innerHTML = S.interfaces.map(i => {
    const ips = i.ipv4.map(a => a.ip + '/' + a.prefix).join(', ') || 'sans IP';
    return `<option value="${esc(i.name)}">${i.active ? '●' : '○'} ${esc(i.name)} — ${esc(i.label)} — ${esc(ips)}</option>`;
  }).join('');
  if(cur && S.interfaces.some(i => i.name === cur)) sel.value = cur;
  else if(!ifaceTouched){
    const wired = S.interfaces.find(i => i.active && i.label !== 'Wi-Fi' && i.ipv4.length) || S.interfaces.find(i => i.active) || S.interfaces[0];
    if(wired) sel.value = wired.name;
  }

  // jobs
  const jobs = Object.values(S.jobs);
  $('jobs').innerHTML = jobs.map(j => `<span class="job"><span class="spin"></span>${esc(j.label)} · ${j.elapsed}s</span>`).join(' ');
  $('btnStop').disabled = !jobs.length;
  $('btnScan').disabled = !!S.jobs.scan;
  $('btnListen').disabled = !!S.jobs.listen || !S.root;

  // aliases
  $('aliases').innerHTML = S.aliases.map(a => `<span class="alias" title="${esc(a.keep_reason)}">${esc(a.iface)} ${esc(a.ip)}<button data-rm="${esc(a.iface)}|${esc(a.ip)}" title="Retirer l'alias">×</button></span>`).join('');

  // rows
  const list = S.devices.filter(d => filter === 'all' || (filter === 'pharos' ? d.kind === 'pharos' : d.kind !== 'other'));
  $('empty').style.display = list.length ? 'none' : 'block';
  if(!list.length && S.devices.length){ $('empty').innerHTML = `<b>${S.devices.length} équipement(s) masqué(s) par le filtre</b>Clique sur <em>Tous</em> pour les voir.`; }
  $('rows').innerHTML = list.map(d => {
    const name = d.model || (d.kind === 'pharos' ? 'PharOS' : d.title) || (d.kind === 'tplink' ? 'TP-Link' : 'Équipement');
    const svc = (d.ports||[]).map(p => `<span class="tag">${{22:'SSH',80:'HTTP',443:'HTTPS'}[p]||p}</span>`).join('')
      + (d.tdp ? '<span class="tag tdp">TDP</span>' : '')
      + (d.ip && !d.in_range ? '<span class="tag out">hors plage</span>' : '');
    return `<tr class="row ${d.id === selected ? 'sel' : ''}" data-id="${esc(d.id)}">
      <td><span class="dot ${d.kind}"></span>${esc(name)}</td>
      <td class="mono">${esc(d.ip || '—')}${d.ips.length > 1 ? ` <span class="hint">+${d.ips.length-1}</span>` : ''}</td>
      <td class="mono">${esc(d.mac || '—')}</td>
      <td>${esc(d.vendor || '—')}</td>
      <td>${esc(d.iface || '—')}</td>
      <td>${svc || '<span class="hint">—</span>'}</td>
      <td class="hint">${esc(d.last_seen || '')}</td></tr>`;
  }).join('');

  renderDetail();

  // log
  if(S.log.length !== logLen){
    const el = $('log'), atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 30;
    el.innerHTML = S.log.map(l => `<div class="${l.level}"><span class="t">${l.t}</span>${esc(l.msg)}</div>`).join('');
    if(atBottom) el.scrollTop = el.scrollHeight;
    logLen = S.log.length;
  }
}

let detailKey = '';
function renderDetail(){
  const d = S.devices.find(x => x.id === selected);
  const key = d ? JSON.stringify([d, S.root, Object.keys(S.jobs)]) : '';
  if(key === detailKey) return;   // évite d'écraser les champs en cours de saisie
  const typing = document.activeElement && $('detail').contains(document.activeElement) && document.activeElement.tagName === 'INPUT';
  if(typing && d) return;
  detailKey = key;
  if(!d){ $('detail').innerHTML = '<div class="empty" style="padding:40px 0"><b>Sélectionne un équipement</b>pour l\'ouvrir, t\'y connecter ou changer son IP.</div>'; return; }
  const kindLbl = {pharos:'PharOS', tplink:'TP-Link', other:'Équipement'}[d.kind];
  const busy = Object.keys(S.jobs).length > 0;
  const hasWeb = (d.ports||[]).some(p => p === 80 || p === 443);
  const guessNet = d.ip ? d.ip.split('.').slice(0,3).join('.') + '.' : '';
  $('detail').innerHTML = `
    <h2>${esc(d.model || kindLbl)}</h2>
    <div class="sub">${esc(d.title || (d.kind === 'pharos' ? 'Interface PharOS détectée' : 'Identification partielle'))}</div>
    <dl>
      <dt>IP</dt><dd class="mono">${esc(d.ips.join(', ') || '—')}</dd>
      <dt>MAC</dt><dd class="mono">${esc(d.mac || '—')}</dd>
      <dt>Fabricant</dt><dd>${esc(d.vendor || 'inconnu')}</dd>
      <dt>Interface</dt><dd>${esc(d.iface || '—')}</dd>
      <dt>Joignable</dt><dd>${d.reachable === null ? '<span class="hint">non testé</span>' : d.reachable ? 'oui' : 'non'}${d.ip && !d.in_range ? ' · <span style="color:var(--warn)">hors de tes plages</span>' : ''}</dd>
      <dt>SSH</dt><dd class="mono">${esc(d.ssh || '—')}</dd>
      <dt>Serveur web</dt><dd>${esc(d.server || '—')}</dd>
      <dt>Source</dt><dd>${esc(d.sources.join(', '))}</dd>
    </dl>
    <div class="actions">
      ${d.ip && !d.in_range ? `<button class="primary" data-act="reach" ${busy||!S.root?'disabled':''}>Rendre joignable (alias ${esc(guessNet)}x sur ${esc(d.iface || $('iface').value)})</button>` : ''}
      <button ${d.ip?'':'disabled'} data-act="web" class="${d.in_range && hasWeb ? 'primary' : ''}">Ouvrir l'interface web (https)</button>
      <button ${d.ip?'':'disabled'} data-act="webhttp">Ouvrir en http</button>
      <button ${d.ip?'':'disabled'} data-act="ssh">Session SSH dans Terminal…</button>
      <button ${d.ip&&!busy?'':'disabled'} data-act="refresh">Ré-identifier</button>
    </div>
    <div class="card">
      <h3>Changer l'adresse IP</h3>
      <ol>
        <li>Ouvre l'interface web et connecte-toi (usine : <span class="mono">admin / admin</span>).</li>
        <li><b>Network</b> → <b>LAN</b> : passe en <em>Static</em>, saisis la nouvelle IP, le masque et la passerelle, puis <b>Save</b>.</li>
        <li>Indique la nouvelle IP ci-dessous : l'outil ajoute l'alias nécessaire et attend que l'équipement revienne.</li>
      </ol>
      <div class="row2"><input type="text" id="newIp" placeholder="Nouvelle IP ex. 192.168.3.20" class="mono"><input type="number" id="newPfx" value="24" min="8" max="30" style="flex:none;width:58px" title="Préfixe"></div>
      <button data-act="watch" ${busy?'disabled':''}>Suivre la nouvelle IP</button>
      <p class="hint" style="margin:8px 0 0">Le reste de la configuration (mode, SSID, sécurité…) se fait dans l'interface web PharOS, comme avec Pharos Control.</p>
    </div>
    <div class="card">
      <h3>Session SSH</h3>
      <div class="row2"><input type="text" id="sshUser" value="admin" class="mono"></div>
      <p class="hint" style="margin:0">Mêmes identifiants que l'interface web. Algorithmes anciens autorisés pour les vieux firmwares.</p>
    </div>`;
}

document.addEventListener('click', async e => {
  const row = e.target.closest('tr.row');
  if(row){ selected = row.dataset.id; detailKey=''; render(); return; }
  const rm = e.target.closest('[data-rm]');
  if(rm){ const [iface, ip] = rm.dataset.rm.split('|'); return api('/api/alias/remove', {iface, ip}).catch(()=>{}); }
  const f = e.target.closest('#filter button');
  if(f){ filter = f.dataset.f; document.querySelectorAll('#filter button').forEach(b => b.classList.toggle('on', b === f)); render(); return; }
  const a = e.target.closest('[data-act]');
  if(!a) return;
  const d = S.devices.find(x => x.id === selected); if(!d) return;
  const act = a.dataset.act;
  try{
    if(act === 'reach') await api('/api/reach', {id:d.id, iface:d.iface || $('iface').value, prefix:24});
    if(act === 'web') await api('/api/open', {ip:d.ip, scheme:'https'});
    if(act === 'webhttp') await api('/api/open', {ip:d.ip, scheme:'http'});
    if(act === 'ssh') await api('/api/ssh', {ip:d.ip, user:($('sshUser')||{}).value || 'admin'});
    if(act === 'refresh') await api('/api/refresh', {id:d.id});
    if(act === 'watch'){
      const ip = $('newIp').value.trim();
      if(!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return toast('Saisis une IP valide');
      await api('/api/watch', {ip, prefix:+$('newPfx').value || 24, iface:d.iface || $('iface').value});
    }
  }catch(_){}
});

$('iface').addEventListener('change', () => { ifaceTouched = true; });
$('btnScan').onclick = () => api('/api/scan', {iface:$('iface').value, factory:$('factory').checked, full:$('full').checked, extra:$('extra').value}).catch(()=>{});
$('btnListen').onclick = () => api('/api/listen', {iface:$('iface').value, seconds:+$('secs').value || 60}).catch(()=>{});
$('btnStop').onclick = () => api('/api/stop').catch(()=>{});

refresh(); setInterval(refresh, 1000);
</script>
</body>
</html>"""

if __name__ == "__main__":
    main()
