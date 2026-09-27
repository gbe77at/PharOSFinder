#!/usr/bin/env python3
"""
Pharos Finder — découverte et accès aux équipements TP-Link PharOS (CPE510, CPE710…)
sur macOS, Windows et Linux.

Inspiré de Pharos Control (TP-Link) et QNAP Finder :
  • balayage ARP des réseaux de chaque interface active ;
  • sondage des plages d'usine PharOS (192.168.0.254 par défaut) via un alias IP temporaire ;
  • écoute passive du câble (tcpdump sur macOS/Linux, socket brute sur Windows) : ARP, DHCP
    et trafic TDP (UDP 20002, le port de découverte utilisé par Pharos Control) — trouve un
    équipement même s'il est dans une plage IP inconnue ;
  • identification : préfixe MAC TP-Link, page web (titre / « PharOS » / modèle CPE-WBS),
    bannière SSH (port 22, canal de gestion Pharos Control) ;
  • accès : alias automatique pour rendre l'équipement joignable, ouverture de l'interface
    web, session SSH, assistant de changement d'IP avec suivi de la nouvelle adresse.

Python 3.8+ standard, aucune dépendance. Lancer en administrateur (sudo sur macOS/Linux,
« Exécuter en tant qu'administrateur » sur Windows) pour les alias IP et l'écoute.
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
import struct
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import finder_vendors as fv  # noqa: E402  (protocoles UniFi, NETGEAR, QNAP, Tuya cloud)

VERSION = "1.0"
IS_MAC = platform.system() == "Darwin"
IS_WIN = os.name == "nt"
IS_LINUX = platform.system() == "Linux"
PLATFORM = "macos" if IS_MAC else "windows" if IS_WIN else "linux"


def _is_admin():
    if IS_WIN:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


IS_ROOT = _is_admin()
SUDO_USER = os.environ.get("SUDO_USER")
# Pas de fenêtre console qui clignote pour chaque ping/arp lancé depuis l'exe Windows.
NO_WINDOW = 0x08000000 if IS_WIN else 0

PHAROS_DEFAULT_IP = "192.168.0.254"
FACTORY_NETS = ["192.168.0.0/24", "192.168.1.0/24"]
PRIORITY_HOSTS = [254, 1, 253, 2, 100, 250]
# Modèles visés en priorité : CPE510 et CPE710 (le motif couvre aussi CPE210/610, WBS510…).
PHAROS_MODEL_RE = re.compile(r"\b((?:CPE|WBS)\d{3}[A-Z]?)\b", re.I)

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
    "f4:ec:38", "f8:1a:67", "6c:4c:bc", "50:7b:9d",
}

SKIP_IFACE_PREFIXES = ("lo", "gif", "stf", "utun", "awdl", "llw", "anpi", "ap", "bridge", "vmenet", "docker", "veth")

# ─────────────────────────── état partagé ───────────────────────────

LOCK = threading.RLock()
DEVICES = {}        # id -> device dict
LOG = []            # entrées de journal
JOBS = {}           # nom -> {"label", "started", "proc"?}
ALIASES = []        # [{"iface", "ip", "mask", "keep_reason"}]
VENDOR_CACHE = {}
CONFLICTS = set()
VENDOR_LOCK = threading.Lock()
TOKEN = secrets.token_urlsafe(16)


def log(msg, level="info"):
    entry = {"t": time.strftime("%H:%M:%S"), "level": level, "msg": msg}
    with LOCK:
        LOG.append(entry)
        del LOG[:-500]
    print(f"[{entry['t']}] {level.upper():5} {msg}", flush=True)


def run(cmd, timeout=15, encoding=None):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              encoding=encoding, errors="replace", creationflags=NO_WINDOW)
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
    """macOS : device -> nom lisible (« USB 10/100/1000 LAN », « Wi-Fi »…). Cache 30 s."""
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


def _ipv4_entry(ip, prefix):
    prefix = int(prefix)
    return {"ip": ip, "mask": str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask), "prefix": prefix}


def _mac_interfaces():
    ports = hardware_ports()
    res = []
    for i in parse_ifconfig(run(["ifconfig"]).stdout):
        if i["name"].startswith(SKIP_IFACE_PREFIXES) or not i["mac"]:
            continue
        i["label"] = ports.get(i["name"], i["name"])
        i["wireless"] = i["label"] == "Wi-Fi"
        i["active"] = (i["status"] == "active") if i["status"] is not None else bool(i["ipv4"])
        res.append(i)
    return res


LINUX_SKIP = SKIP_IFACE_PREFIXES + ("br-", "virbr", "tun", "tap", "wg", "tailscale", "zt", "cni", "flannel")


def _linux_interfaces():
    try:
        data = json.loads(run(["ip", "-j", "addr", "show"]).stdout or "[]")
    except ValueError:
        data = []
    res = []
    for d in data:
        name = d.get("ifname", "")
        mac = norm_mac(d.get("address") or "")
        if not mac or name.startswith(LINUX_SKIP) or d.get("link_type") not in (None, "ether"):
            continue
        wireless = os.path.exists(f"/sys/class/net/{name}/wireless")
        ipv4 = [_ipv4_entry(a["local"], a["prefixlen"]) for a in d.get("addr_info", [])
                if a.get("family") == "inet" and a.get("local")]
        flags = d.get("flags", [])
        up = "LOWER_UP" in flags or d.get("operstate") == "UP"
        res.append({"name": name, "mac": mac, "ipv4": ipv4, "status": "active" if up else "inactive",
                    "label": ("Wi-Fi" if wireless else "Ethernet") + f" ({name})", "wireless": wireless,
                    "active": up})
    return res


WIN_IFACE_PS = (
    "$ErrorActionPreference='SilentlyContinue';"
    "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
    "$a=@(Get-NetAdapter | Select-Object Name,InterfaceDescription,ifIndex,Status,MacAddress,"
    "@{n='Media';e={[string]$_.PhysicalMediaType}},@{n='St';e={[string]$_.Status}});"
    "$i=@(Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceIndex,IPAddress,PrefixLength,"
    "@{n='State';e={[string]$_.AddressState}});"
    "ConvertTo-Json -Compress -Depth 3 -InputObject @{a=$a;i=$i}"
)


def _windows_interfaces_api():
    """Interfaces via GetAdaptersAddresses (iphlpapi) : instantané et indépendant de la langue."""
    import ctypes
    from ctypes import wintypes

    class SOCKET_ADDRESS(ctypes.Structure):
        _fields_ = [("lpSockaddr", ctypes.c_void_p), ("iSockaddrLength", ctypes.c_int)]

    class UNICAST(ctypes.Structure):
        pass

    UNICAST._fields_ = [("Length", wintypes.ULONG), ("Flags", wintypes.DWORD),
                        ("Next", ctypes.POINTER(UNICAST)), ("Address", SOCKET_ADDRESS),
                        ("PrefixOrigin", ctypes.c_int), ("SuffixOrigin", ctypes.c_int),
                        ("DadState", ctypes.c_int), ("ValidLifetime", wintypes.ULONG),
                        ("PreferredLifetime", wintypes.ULONG), ("LeaseLifetime", wintypes.ULONG),
                        ("OnLinkPrefixLength", ctypes.c_uint8)]

    class ADAPTER(ctypes.Structure):
        pass

    ADAPTER._fields_ = [("Length", wintypes.ULONG), ("IfIndex", wintypes.DWORD),
                        ("Next", ctypes.POINTER(ADAPTER)), ("AdapterName", ctypes.c_char_p),
                        ("FirstUnicastAddress", ctypes.POINTER(UNICAST)),
                        ("FirstAnycastAddress", ctypes.c_void_p), ("FirstMulticastAddress", ctypes.c_void_p),
                        ("FirstDnsServerAddress", ctypes.c_void_p), ("DnsSuffix", ctypes.c_wchar_p),
                        ("Description", ctypes.c_wchar_p), ("FriendlyName", ctypes.c_wchar_p),
                        ("PhysicalAddress", ctypes.c_ubyte * 8), ("PhysicalAddressLength", wintypes.ULONG),
                        ("Flags", wintypes.ULONG), ("Mtu", wintypes.ULONG), ("IfType", wintypes.DWORD),
                        ("OperStatus", ctypes.c_int)]

    gaa = ctypes.windll.iphlpapi.GetAdaptersAddresses
    size = wintypes.ULONG(32768)
    for _ in range(4):
        buf = ctypes.create_string_buffer(size.value)
        # AF_INET, sans anycast/multicast/DNS ; les cartes débranchées sont incluses.
        rc = gaa(2, 0x0002 | 0x0004 | 0x0008, None, buf, ctypes.byref(size))
        if rc != 111:  # ERROR_BUFFER_OVERFLOW : on recommence avec la taille demandée
            break
    if rc != 0:
        raise OSError(f"GetAdaptersAddresses a renvoyé {rc}")
    res = []
    node = ctypes.cast(buf, ctypes.POINTER(ADAPTER))
    while node:
        a = node.contents
        node = a.Next
        if a.IfType in (24, 131) or a.PhysicalAddressLength != 6:  # boucle locale, tunnels
            continue
        mac = ":".join(f"{b:02x}" for b in a.PhysicalAddress[:6])
        ipv4, u = [], a.FirstUnicastAddress
        while u:
            ua = u.contents
            u = ua.Next
            if not ua.Address.lpSockaddr or ua.DadState == 2:  # doublon
                continue
            raw = ctypes.string_at(ua.Address.lpSockaddr, 8)
            if raw[0] == 2:  # AF_INET
                ipv4.append(_ipv4_entry(socket.inet_ntoa(raw[4:8]), ua.OnLinkPrefixLength))
        desc = a.Description or a.FriendlyName
        wireless = a.IfType == 71 or "wi-fi" in desc.lower() or "wireless" in desc.lower()
        up = a.OperStatus == 1
        res.append({"name": a.FriendlyName, "mac": mac, "ipv4": ipv4,
                    "status": "active" if up else "inactive", "label": desc, "wireless": wireless,
                    "active": up, "index": a.IfIndex})
    return res


def _windows_interfaces():
    try:
        return _windows_interfaces_api()
    except Exception as e:  # noqa: BLE001
        log(f"API réseau Windows indisponible ({e}) : repli sur PowerShell", "warn")
    return _windows_interfaces_ps()


def _windows_interfaces_ps():
    r = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", WIN_IFACE_PS], timeout=90, encoding="utf-8")
    try:
        data = json.loads((r.stdout or "").strip().lstrip("﻿") or "{}")
    except ValueError:
        log(f"Lecture des interfaces Windows impossible : {r.stderr.strip()[:200]}", "error")
        return []
    ips = {}
    for a in data.get("i") or []:
        if str(a.get("State")) in ("Duplicate", "Invalid", "0", "2"):
            continue
        ips.setdefault(a.get("InterfaceIndex"), []).append(_ipv4_entry(a["IPAddress"], a["PrefixLength"]))
    res = []
    for a in data.get("a") or []:
        mac = norm_mac((a.get("MacAddress") or "").replace("-", ":"))
        if not mac:
            continue
        media = (a.get("Media") or "").lower()
        desc = a.get("InterfaceDescription") or a["Name"]
        wireless = "802.11" in media or "wireless" in desc.lower() or "wi-fi" in desc.lower()
        up = (a.get("St") or "") == "Up"
        res.append({"name": a["Name"], "mac": mac, "ipv4": ips.get(a.get("ifIndex"), []),
                    "status": "active" if up else "inactive", "label": desc, "wireless": wireless,
                    "active": up, "index": a.get("ifIndex")})
    return res


# La lecture des interfaces coûte ~1 s sous Windows (PowerShell) : on la met en cache.
_IFACE_CACHE = {"t": 0.0, "v": None}
_IFACE_LOCK = threading.Lock()
IFACE_TTL = 2.0 if IS_WIN else 0.0


def invalidate_interfaces():
    _IFACE_CACHE["t"] = 0.0


def list_interfaces():
    with _IFACE_LOCK:
        if _IFACE_CACHE["v"] is None or time.time() - _IFACE_CACHE["t"] >= IFACE_TTL:
            raw = _windows_interfaces() if IS_WIN else _linux_interfaces() if IS_LINUX else _mac_interfaces()
            _IFACE_CACHE.update(t=time.time(), v=raw)
        raw = _IFACE_CACHE["v"]
    res = []
    for i in raw:
        i = dict(i)
        with LOCK:
            i["aliases"] = [a["ip"] for a in ALIASES if a["iface"] == i["name"]]
        res.append(i)
    res.sort(key=lambda x: (not x["active"], not x["ipv4"], x.get("wireless", False), x["name"]))
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

WIN_COEXIST = set()   # interfaces où l'on a activé la coexistence DHCP/statique


def _prefix_of(mask):
    return ipaddress.IPv4Network("0.0.0.0/" + mask).prefixlen


def _win_add_address(iface, ip, mask):
    cmd = ["netsh", "interface", "ipv4", "add", "address", f"name={iface}", f"address={ip}",
           f"mask={mask}", "store=active"]
    r = run(cmd)
    if r.returncode == 0:
        return r
    # Interface en DHCP (ou en 169.254 sans serveur DHCP) : Windows 10 2004+ accepte une
    # adresse statique en plus si la coexistence DHCP/statique est activée.
    en = run(["netsh", "interface", "ipv4", "set", "interface", f"interface={iface}",
              "dhcpstaticipcoexistence=enabled"])
    if en.returncode == 0:
        WIN_COEXIST.add(iface)
        r = run(cmd)
    return r


def add_alias(iface, ip, mask, reason=""):
    if not IS_ROOT:
        raise RuntimeError("droits administrateur requis pour ajouter une adresse temporaire")
    if IS_MAC:
        r = run(["ifconfig", iface, "alias", ip, mask])
    elif IS_WIN:
        r = _win_add_address(iface, ip, mask)
    else:
        r = run(["ip", "addr", "add", f"{ip}/{_prefix_of(mask)}", "dev", iface])
    if r.returncode != 0:
        msg = (r.stderr.strip() or r.stdout.strip())[:300]
        raise RuntimeError(f"alias {ip} sur {iface} refusé : {msg}")
    with LOCK:
        ALIASES.append({"iface": iface, "ip": ip, "mask": mask, "keep_reason": reason})
    invalidate_interfaces()
    log(f"Alias temporaire {ip}/{mask} ajouté sur {iface}")
    # Windows fait une détection de doublon (DAD) avant d'utiliser l'adresse.
    time.sleep(2.5 if IS_WIN else 0.8)


def remove_alias(iface, ip):
    with LOCK:
        entry = next((a for a in ALIASES if a["iface"] == iface and a["ip"] == ip), None)
        if entry:
            ALIASES.remove(entry)
        still = any(a["iface"] == iface for a in ALIASES)
    if IS_MAC:
        run(["ifconfig", iface, "-alias", ip])
    elif IS_WIN:
        run(["netsh", "interface", "ipv4", "delete", "address", f"name={iface}", f"address={ip}"])
        if iface in WIN_COEXIST and not still:
            run(["netsh", "interface", "ipv4", "set", "interface", f"interface={iface}",
                 "dhcpstaticipcoexistence=disabled"])
            WIN_COEXIST.discard(iface)
    else:
        mask = entry["mask"] if entry else "255.255.255.0"
        run(["ip", "addr", "del", f"{ip}/{_prefix_of(mask)}", "dev", iface])
    invalidate_interfaces()
    log(f"Alias {ip} retiré de {iface}")


def cleanup_aliases():
    try:
        cleanup_vlans()
    except Exception:
        pass
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
    if IS_WIN:
        # Windows renvoie 0 même pour « Impossible de joindre l'hôte » : on cherche « TTL= ».
        r = run(["ping", "-n", "1", "-w", str(timeout_ms), str(ip)], timeout=4)
        return "ttl=" in (r.stdout or "").lower()
    cmd = ["ping", "-c", "1", "-n"]
    cmd += ["-W", str(timeout_ms)] if IS_MAC else ["-W", "1"]
    cmd.append(str(ip))
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=3).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def probe_host(ip):
    ip = str(ip)
    return ping(ip, 1000) or tcp_open(ip, 443, 1.0) or tcp_open(ip, 80, 1.0) or tcp_open(ip, 22, 1.0)


def sweep(hosts, workers=64, probe=ping):
    alive = []
    with cf.ThreadPoolExecutor(workers) as ex:
        for ip, ok in zip(hosts, ex.map(probe, hosts)):
            if ok:
                alive.append(str(ip))
    return alive


ARP_RE = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]{11,17})(?: \[\w+\])? on (\S+)")
WIN_ARP_IF = re.compile(r"^\S.*?(\d+\.\d+\.\d+\.\d+)\s+-+\s+0x([0-9a-fA-F]+)")
WIN_ARP_ROW = re.compile(r"^\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s")
LINUX_NEIGH = re.compile(r"^(\d+\.\d+\.\d+\.\d+) dev (\S+) lladdr ([0-9a-fA-F:]{17})")


def parse_arp_windows(text, index_to_name):
    entries, iface = [], None
    for line in text.splitlines():
        m = WIN_ARP_IF.match(line)
        if m:
            iface = index_to_name.get(int(m.group(2), 16), m.group(1))
            continue
        m = WIN_ARP_ROW.match(line)
        if m and iface:
            entries.append((m.group(1), m.group(2).replace("-", ":"), iface))
    return entries


def arp_table():
    if IS_MAC:
        raw = [(m.group(1), m.group(2), m.group(3)) for m in ARP_RE.finditer(run(["arp", "-an"]).stdout)]
    elif IS_WIN:
        idx = {i.get("index"): i["name"] for i in list_interfaces()}
        raw = parse_arp_windows(run(["arp", "-a"]).stdout, idx)
    else:
        raw = []
        for line in run(["ip", "-4", "neigh", "show"]).stdout.splitlines():
            m = LINUX_NEIGH.match(line)
            if m and "FAILED" not in line and "INCOMPLETE" not in line:
                raw.append((m.group(1), m.group(3), m.group(2)))
    entries = []
    for ip, mac, iface in raw:
        mac = norm_mac(mac)
        if not mac or mac == "ff:ff:ff:ff:ff:ff" or is_multicast_mac(mac):
            continue
        entries.append({"ip": ip, "mac": mac, "iface": iface})
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
            return s.recv(256).decode("utf-8", "ignore").splitlines()[0].strip() or None
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
    host = f"[{ip}]" if ":" in ip else ip
    if 443 in open_ports:
        tries.append(f"https://{host}/")
    if 80 in open_ports:
        tries.append(f"http://{host}/")
    for url in tries:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 PharosFinder"})
            with opener.open(req, timeout=10) as r:  # PharOS répond lentement
                body = r.read(300_000).decode("utf-8", "ignore")
                final = r.geturl()
                server = r.headers.get("Server")
        except Exception:
            continue
        t = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
        title = re.sub(r"\s+", " ", t.group(1)).strip()[:120] if t else None
        low = body.lower()
        # Le titre d'abord (« CPE510 », « CPE710 »…), puis le reste de la page.
        model = PHAROS_MODEL_RE.search(title or "") or PHAROS_MODEL_RE.search(body)
        return {
            "web": final or url,
            "title": title,
            "server": server,
            "pharos_hint": "pharos" in low,
            "tplink_hint": "tp-link" in low or "tplink" in low or "tp_link" in low,
            "model": model.group(1).upper() if model else None,
        }
    return None


# ─────────────────────────── modèle d'équipement ───────────────────────────

def _new_device(key, mac, ip):
    return {"id": key, "mac": mac, "ip": ip, "ips": [], "vendor": None, "kind": "other",
            "iface": None, "model": None, "title": None, "server": None, "ports": [],
            "ssh": None, "sources": [], "tdp": False, "pharos_hint": False,
            "tplink_hint": False, "web": None, "reachable": None, "last_seen": None,
            "fingerprinted": False, "ipv6": None, "web_local": None, "firmware": None,
            "announced": None, "name": None, "services": [], "tuya": None, "unifi": None,
            "netgear": None, "qnap": None, "fw_modules": [], "update_available": False}


KINDS = ("pharos", "tplink", "unifi", "netgear", "qnap", "tuya", "amazon", "other")   # ordre d'affichage


def classify(d):
    text = " ".join(filter(None, [d.get("title"), d.get("model"), d.get("server")])).lower()
    vendor = (d.get("vendor") or "").lower()
    if d.get("pharos_hint") or "pharos" in text or (d.get("model") and PHAROS_MODEL_RE.match(d["model"])):
        d["kind"] = "pharos"
    elif d.get("tuya") or "tuya" in vendor:
        d["kind"] = "tuya"
    elif d.get("unifi") or "ubiquiti" in vendor:
        d["kind"] = "unifi"
    elif d.get("netgear") or "netgear" in vendor:
        d["kind"] = "netgear"
    elif d.get("qnap") or "qnap" in vendor or "_qdiscover._tcp" in (d.get("services") or []):
        d["kind"] = "qnap"
    elif "amazon" in vendor or any(sv.startswith("_amzn") for sv in d.get("services") or []):
        d["kind"] = "amazon"
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
        if not mac:  # vu sans MAC (Tuya, mDNS…) : rattache à l'équipement qui a déjà cette IP
            key = next((k for k, v in DEVICES.items() if v["ip"] == ip), f"ip:{ip}")
        else:
            key = mac
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
            others = [o["mac"] for o in DEVICES.values() if o is not d and o["ip"] == ip and o["mac"]]
            if mac and others and (ip, mac) not in CONFLICTS:
                CONFLICTS.add((ip, mac))
                log(f"Conflit d'adresse : {ip} est utilisée par {mac} et {', '.join(others)}. "
                    "Débranche l'un des deux ou change son IP.", "warn")
        if source and source not in d["sources"]:
            d["sources"].append(source)
        for k, v in fields.items():
            if k in ("tdp", "pharos_hint", "tplink_hint"):
                d[k] = d[k] or bool(v)
            elif k == "services" and v:
                d[k] = sorted(set(d.get(k) or []) | set(v))
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
        if not d or not (d["ip"] or d.get("ipv6")):
            return
        ip4, mac = d["ip"], d["mac"]
        ip = ip4 or d["ipv6"]  # IPv6 link-local quand l'IPv4 est inconnue
    vendor = (vendor_of(mac) or lookup_vendor_online(mac)) if mac else None
    probe_ports = (22, 80, 443) + (AMAZON_PORTS if vendor and "amazon" in vendor.lower() else ())
    open_ports = [p for p in probe_ports if tcp_open(ip, p)]
    info = {"ports": open_ports, "reachable": bool(open_ports) or ping(ip, 800), "fingerprinted": True}
    if vendor and "amazon" in vendor.lower():
        with LOCK:
            services = list(DEVICES.get(dev_id, {}).get("services") or [])
        info["model"] = amazon_model(open_ports, services)
    if 22 in open_ports:
        info["ssh"] = ssh_banner(ip)
    web = http_probe(ip, open_ports) if (80 in open_ports or 443 in open_ports) else None
    if web:
        info.update(web)
    if vendor:
        info["vendor"] = vendor
    if not ip4 and web:
        info["web_local"] = ensure_tunnel(dev_id, ip, 443 if 443 in open_ports else 80)
    if ip4 and vendor and "qnap" in vendor.lower():
        threading.Thread(target=probe_qnap, args=(dev_id,), daemon=True).start()
    d = upsert(mac=mac, ip=ip4, **info)
    if d:
        label = {"pharos": "PharOS", "tplink": "TP-Link"}.get(d["kind"], "équipement")
        extra = f" — {d['model']}" if d.get("model") else (f" — « {d['title']} »" if d.get("title") else "")
        log(f"{label} {ip} ({mac or 'MAC ?'}){extra} · ports {open_ports or 'aucun'}",
            "ok" if d["kind"] == "pharos" else "info")


def fingerprint_many(ids):
    with cf.ThreadPoolExecutor(8) as ex:
        list(ex.map(fingerprint, ids))


NDP_MAC = re.compile(r"^(fe80:[0-9a-f:]+)(?:%(\S+))?\s+([0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5})\s+(\S+)", re.I | re.M)
NETSH_V6 = re.compile(r"(fe80:[0-9a-f:]+)\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})", re.I)
LINUX_V6 = re.compile(r"^(fe80:[0-9a-f:]+) (?:dev \S+ )?lladdr ([0-9a-f:]{17})", re.I | re.M)


def ipv6_neighbors(iface):
    """Voisins IPv6 link-local du câble : [(fe80::…%scope, mac)]. Indépendant de la plage IPv4."""
    name = iface["name"]
    if IS_WIN:
        scope = str(iface.get("index") or "")
        if not scope:
            return []
        run(["ping", "-n", "2", "-w", "800", f"ff02::1%{scope}"], timeout=10)
        out = run(["netsh", "interface", "ipv6", "show", "neighbors", f"interface={scope}"]).stdout
        rows = [(a, m.replace("-", ":")) for a, m in NETSH_V6.findall(out)]
    elif IS_MAC:
        scope = name
        run(["ping6", "-c", "2", "-i", "1", f"ff02::1%{name}"], timeout=10)
        rows = [(a, m) for a, sc, m, i in NDP_MAC.findall(run(["ndp", "-an"]).stdout) if i == name]
    else:
        scope = name
        run(["ping", "-6", "-c", "2", "-i", "1", f"ff02::1%{name}"], timeout=10)
        rows = LINUX_V6.findall(run(["ip", "-6", "neigh", "show", "dev", name]).stdout)
    res = []
    for addr, mac in rows:
        mac = norm_mac(mac)
        if mac and mac != iface["mac"] and not is_multicast_mac(mac):
            res.append((f"{addr}%{scope}", mac))
    return res


def discover_ipv6(iface):
    """Trouve un Pharos déjà configuré dans une plage IPv4 inconnue, sans reset ni écoute."""
    log(f"Recherche IPv6 link-local sur {iface['name']} (trouve un Pharos quelle que soit son IP)…")
    neigh = ipv6_neighbors(iface)
    with LOCK:
        known = {d["mac"] for d in DEVICES.values() if d["ip"] and d["mac"]}
    ids = []
    for ll, mac in neigh:
        if mac in known:
            continue
        vendor = vendor_of(mac) or lookup_vendor_online(mac)
        if vendor not in ("TP-Link", None):
            continue
        d = upsert(mac=mac, source="IPv6", iface=iface["name"], ipv6=ll)
        if d:
            ids.append(d["id"])
    log(f"IPv6 : {len(neigh)} voisin(s), {len(ids)} candidat(s) TP-Link/inconnu(s) sans IPv4 connue.",
        "ok" if ids else "info")
    if ids:
        fingerprint_many(ids)


# ─────────────────── VLAN de gestion (PharOS « Management VLAN ») ───────────────────

VLAN_IFACES = []   # interfaces VLAN créées par l'outil, détruites à la fermeture
COMMON_VLANS = [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 20, 30, 40, 50, 99, 100, 101, 200, 254, 1000]


def _vlan_create(parent, vid, ip, mask):
    if IS_MAC:
        name = run(["ifconfig", "vlan", "create"]).stdout.strip()
        if not name:
            raise RuntimeError("création d'interface VLAN refusée")
        run(["ifconfig", name, "vlan", str(vid), "vlandev", parent])
        run(["ifconfig", name, "inet", ip, "netmask", mask, "up"])
    else:
        name = f"pf{vid}"
        run(["ip", "link", "add", "link", parent, "name", name, "type", "vlan", "id", str(vid)])
        run(["ip", "addr", "add", f"{ip}/{_prefix_of(mask)}", "dev", name])
        run(["ip", "link", "set", name, "up"])
    VLAN_IFACES.append(name)
    invalidate_interfaces()
    return name


def _vlan_destroy(name):
    run(["ifconfig", name, "destroy"] if IS_MAC else ["ip", "link", "del", name])
    if name in VLAN_IFACES:
        VLAN_IFACES.remove(name)
    invalidate_interfaces()


def cleanup_vlans():
    for name in list(VLAN_IFACES):
        _vlan_destroy(name)


def _ping_via(name, ip):
    cmd = ["ping", "-c", "2", "-W", "700", "-b", name, ip] if IS_MAC else ["ping", "-c", "2", "-W", "1", "-I", name, ip]
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=6).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def job_vlan_probe(iface_name, target, vlans):
    """Cherche le VLAN de gestion d'un Pharos qui s'annonce mais ignore le trafic non étiqueté.
    Ne vise que l'adresse `target` ; chaque interface VLAN d'essai est détruite aussitôt."""
    if IS_WIN:
        raise RuntimeError("le test de VLAN n'est pas disponible sous Windows")
    if not IS_ROOT:
        raise RuntimeError("droits administrateur requis")
    net = ipaddress.ip_network(f"{target}/24", strict=False)
    # Une adresse de l'outil dans ce /24 sur l'interface physique capterait la route : on la retire.
    with LOCK:
        mine = [a for a in ALIASES if a["iface"] == iface_name and ipaddress.IPv4Address(a["ip"]) in net]
    for a in mine:
        remove_alias(a["iface"], a["ip"])
    local = pick_alias_ip(net, avoid={target})
    log(f"Test des VLAN de gestion sur {iface_name} vers {target} : {', '.join(map(str, vlans))}…")
    for vid in vlans:
        if JOBS.get("vlan", {}).get("stop"):
            log("Test des VLAN interrompu.", "warn")
            return
        name = _vlan_create(iface_name, vid, local, str(net.netmask))
        time.sleep(1.5)
        if _ping_via(name, target):
            log(f"VLAN {vid} : {target} répond ! Interface {name} ({local}) gardée jusqu'à la fermeture. "
                f"Ouvre https://{target}/ puis, dans PharOS, désactive le Management VLAN ou change "
                "l'IP pour ne plus en dépendre.", "ok")
            with LOCK:
                d = next((x for x in DEVICES.values() if x["ip"] == target), None)
            if d:
                fingerprint(d["id"])
            return
        _vlan_destroy(name)
    log(f"Aucun des VLAN testés ne donne accès à {target}. Si tu connais le numéro, indique-le ; "
        "sinon le contrôle d'accès PharOS bloque la gestion et seul un reset la rendra.", "warn")


# ─────────────────── UniFi, NETGEAR, QNAP : découverte locale ───────────────────

def _ifindex(iface):
    if IS_MAC and hasattr(socket, "if_nametoindex"):
        try:
            return socket.if_nametoindex(iface["name"])
        except OSError:
            return None
    return None


def _bind_ip(iface):
    # Windows envoie le broadcast par l'interface de l'adresse liée ; ailleurs on lie à toutes.
    if IS_WIN and iface["ipv4"]:
        return iface["ipv4"][0]["ip"]
    return ""


def discover_vendors(iface):
    """Découverte constructeur sans identifiants : UniFi (UDP 10001), NETGEAR (NSDP)."""
    name, idx, bind = iface["name"], _ifindex(iface), _bind_ip(iface)
    log(f"Découverte UniFi et NETGEAR sur {name}…")
    n = 0
    try:
        for u in fv.ubnt_discover(wait=2.5, bind_ip=bind, ifindex=idx):
            ip = u["ips"][0] if u["ips"] else u.get("sender")
            label = fv.ubnt_model_label(u)
            d = upsert(mac=u["mac"], ip=ip, source="UniFi", iface=name, model=label, firmware=u["firmware"],
                       name=u["hostname"], vendor="Ubiquiti",
                       unifi={"platform": u["platform"], "essid": u["essid"], "serial": u["serial"],
                              "default": u["is_default"]})
            if d:
                n += 1
                state = " · non adopté (réglages d'usine)" if u["is_default"] else ""
                log(f"UniFi : {label} « {u['hostname'] or '?'} » en {ip}, firmware {u['firmware'] or '?'}{state}",
                    "ok")
    except OSError as e:
        log(f"Découverte UniFi impossible : {e}", "warn")
    try:
        host_mac = bytes(int(x, 16) for x in (iface["mac"] or "00:00:00:00:00:00").split(":"))
        for g in fv.nsdp_discover(host_mac, wait=2.5, bind_ip=bind, ifindex=idx):
            d = upsert(mac=g["mac"], ip=g["ip"], source="NSDP", iface=name, model=g["model"], vendor="NETGEAR",
                       name=g["name"], firmware=g["firmware"],
                       netgear={"dhcp": g["dhcp"], "firmware2": g["firmware2"], "location": g["location"],
                                "gateway": g["gateway"], "active_slot": g["active_slot"]})
            if d:
                n += 1
                log(f"NETGEAR : {g['model'] or '?'} « {g['name'] or '?'} » en {g['ip']}, firmware "
                    f"{g['firmware'] or '?'}", "ok")
    except OSError as e:
        log(f"Découverte NETGEAR impossible : {e}", "warn")
    if not n:
        log("Aucun équipement UniFi ou NETGEAR ne s'est annoncé.")


def probe_qnap(dev_id):
    with LOCK:
        d = DEVICES.get(dev_id)
        ip = d["ip"] if d else None
    info = fv.qnap_probe(ip) if ip else None
    if info:
        upsert(mac=d["mac"], ip=ip, source="QNAP", model=info["model"], vendor="QNAP",
               firmware=" ".join(filter(None, [info["firmware"], f"build {info['build']}" if info["build"] else None])),
               name=info["hostname"], web=info["web"], qnap=info)
        log(f"QNAP : {info['model']} « {info['hostname'] or '?'} » en {ip}, QTS {info['firmware'] or '?'}", "ok")


# ─────────────────── Comptes : Tuya cloud, contrôleur UniFi ───────────────────

INTEGRATIONS = {"tuya": {"configured": False, "status": "non configuré", "last_sync": None},
                "unifi": {"configured": False, "status": "non configuré", "last_sync": None}}
_CLIENTS = {}   # vendor -> client (identifiants en mémoire seulement, sauf « mémoriser »)
CONFIG_PATH = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"),
                           "PharosFinder" if IS_WIN else ".pharosfinder", "comptes.json")


def _status(vendor, status, ok=None):
    INTEGRATIONS[vendor]["status"] = status
    if ok is not None:
        INTEGRATIONS[vendor]["ok"] = ok


def configure_account(vendor, b, persist=False):
    if vendor == "tuya":
        if not b.get("access_id") or not b.get("access_secret"):
            raise RuntimeError("Access ID et Access Secret requis")
        _CLIENTS["tuya"] = fv.TuyaCloud(b["access_id"], b["access_secret"], b.get("region") or "eu")
    elif vendor == "unifi":
        if not b.get("url") or not b.get("username"):
            raise RuntimeError("adresse du contrôleur et identifiant requis")
        _CLIENTS["unifi"] = fv.UniFiController(b["url"], b["username"], b.get("password", ""), b.get("site"))
    else:
        raise RuntimeError("compte inconnu")
    INTEGRATIONS[vendor].update(configured=True, status="configuré, pas encore synchronisé")
    if persist:
        save_accounts(vendor, b)
    log(f"Compte {vendor} configuré.", "ok")


def forget_account(vendor):
    _CLIENTS.pop(vendor, None)
    INTEGRATIONS[vendor] = {"configured": False, "status": "non configuré", "last_sync": None}
    save_accounts(vendor, None)
    log(f"Compte {vendor} oublié.")


def save_accounts(vendor, data):
    try:
        cfg = json.load(open(CONFIG_PATH, encoding="utf-8")) if os.path.exists(CONFIG_PATH) else {}
    except (OSError, ValueError):
        cfg = {}
    if data is None:
        cfg.pop(vendor, None)
    else:
        cfg[vendor] = {k: v for k, v in data.items() if k != "persist"}
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    fd = os.open(CONFIG_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f)


def load_accounts():
    try:
        cfg = json.load(open(CONFIG_PATH, encoding="utf-8"))
    except (OSError, ValueError):
        return
    for vendor, data in cfg.items():
        try:
            configure_account(vendor, data)
        except Exception as e:  # noqa: BLE001
            log(f"Compte {vendor} mémorisé illisible : {e}", "warn")


def _tuya_find(dev_id, ip):
    with LOCK:
        for d in DEVICES.values():
            if (d.get("tuya") or {}).get("gw_id") == dev_id:
                return d
        if ip:
            for d in DEVICES.values():
                if d["ip"] == ip and d["kind"] in ("tuya", "other"):
                    return d
    return None


def _tuya_apply(cd, parent=None):
    """Fiche cloud Tuya → équipement de la liste (fusion avec l'annonce locale si elle existe)."""
    cat = fv.tuya_category_label(cd.get("category"))
    info = {"gw_id": cd.get("id"), "product_key": cd.get("product_id"), "category": cd.get("category"),
            "product_name": cd.get("product_name"), "online": cd.get("online", cd.get("is_online")),
            "sub": bool(cd.get("sub")) or parent is not None, "parent": parent,
            "gateway": cd.get("category") in ("wg2", "wg", "wfcon")}
    local = _tuya_find(cd.get("id"), None)
    if local:
        info["version"] = (local.get("tuya") or {}).get("version")
        with LOCK:
            local["tuya"] = dict(local.get("tuya") or {}, **info)
        d = upsert(mac=local["mac"], ip=local["ip"], source="Tuya cloud", name=cd.get("name"), model=cat,
                   title=cd.get("product_name"))
    elif info["sub"]:
        # Capteur Zigbee / BLE : pas d'IP, rattaché à sa passerelle.
        key = f"tuya:{cd.get('id')}"
        with LOCK:
            d = DEVICES.get(key) or _new_device(key, None, None)
            DEVICES[key] = d
            d.update(name=cd.get("name"), model=cat, title=cd.get("product_name"), vendor="Tuya",
                     tuya=info, last_seen=time.strftime("%H:%M:%S"))
            if "Tuya cloud" not in d["sources"]:
                d["sources"].append("Tuya cloud")
            classify(d)
    else:
        d = None   # appareil Wi-Fi non vu sur ce réseau : on ne l'ajoute pas (il est ailleurs)
    return d


def job_tuya_sync():
    c = _CLIENTS.get("tuya")
    if not c:
        raise RuntimeError("compte Tuya non configuré (bouton « Comptes »)")
    _status("tuya", "synchronisation…")
    try:
        devices = c.devices()
    except Exception as e:  # noqa: BLE001
        _status("tuya", f"erreur : {e}", False)
        raise RuntimeError(f"Tuya : {e}. Vérifie l'aide « Comptes » (projet, région, compte Smart Life lié).")
    log(f"Tuya cloud : {len(devices)} appareil(s) sur le compte.", "ok")
    matched = 0
    for cd in devices:
        d = _tuya_apply(cd)
        if d:
            matched += 1
        if cd.get("category") in ("wg2", "wg", "wfcon"):
            try:
                for sub in c.sub_devices(cd["id"]):
                    _tuya_apply(sub, parent=cd.get("name") or cd["id"])
            except Exception as e:  # noqa: BLE001
                log(f"Sous-appareils de {cd.get('name')} illisibles : {e}", "warn")
    # Firmware : un appel par appareil visible.
    with LOCK:
        targets = [d for d in DEVICES.values() if (d.get("tuya") or {}).get("gw_id")]
    for d in targets:
        try:
            mods = c.firmware(d["tuya"]["gw_id"])
        except Exception as e:  # noqa: BLE001
            log(f"Firmware de {d.get('name') or d['tuya']['gw_id']} illisible : {e}", "warn")
            continue
        fw = [{"module": m.get("type_desc") or f"module {m.get('type')}", "channel": m.get("type"),
               "current": m.get("current_version"), "latest": m.get("version"),
               "can_upgrade": bool(m.get("can_upgrade")) or m.get("upgrade_status") == 1,
               "status": m.get("upgrade_status")} for m in mods]
        with LOCK:
            d["fw_modules"] = fw
            d["firmware"] = ", ".join(f"{m['module']} {m['current']}" for m in fw if m["current"]) or d["firmware"]
            d["update_available"] = any(m["can_upgrade"] and m["latest"] and m["latest"] != m["current"] for m in fw)
        time.sleep(0.2)
    INTEGRATIONS["tuya"]["last_sync"] = time.strftime("%H:%M:%S")
    _status("tuya", f"synchronisé ({len(devices)} appareils, {matched} vus sur ce réseau)", True)
    log("Synchronisation Tuya terminée.", "ok")


def job_unifi_sync():
    c = _CLIENTS.get("unifi")
    if not c:
        raise RuntimeError("contrôleur UniFi non configuré (bouton « Comptes »)")
    _status("unifi", "synchronisation…")
    try:
        devs = c.devices()
    except Exception as e:  # noqa: BLE001
        _status("unifi", f"erreur : {e}", False)
        raise RuntimeError(f"contrôleur UniFi : {e}")
    for u in devs:
        mac = norm_mac(u.get("mac") or "")
        latest = u.get("upgrade_to_firmware") or (u.get("version") if not u.get("upgradable") else None)
        d = upsert(mac=mac, ip=u.get("ip"), source="contrôleur UniFi", vendor="Ubiquiti",
                   name=u.get("name"), model=u.get("model_name") or u.get("model"), firmware=u.get("version"),
                   unifi={"adopted": u.get("adopted"), "state": u.get("state"), "type": u.get("type"),
                          "controller": True, "upgradable": bool(u.get("upgradable")), "latest": latest})
        if d:
            with LOCK:
                d["update_available"] = bool(u.get("upgradable"))
    INTEGRATIONS["unifi"]["last_sync"] = time.strftime("%H:%M:%S")
    _status("unifi", f"synchronisé ({len(devs)} équipements)", True)
    log(f"Contrôleur UniFi : {len(devs)} équipement(s).", "ok")


# ─────────────────── actions par équipement ───────────────────

def device_actions(d):
    """Actions proposées dans les interfaces : [{id, label, confirm?}]."""
    acts = []
    if d.get("web") or (d["kind"] in ("netgear", "qnap", "unifi", "tplink", "pharos") and d["ip"]):
        acts.append({"id": "web", "label": "Ouvrir l'interface web"})
    u = d.get("unifi") or {}
    if u.get("controller") and d["mac"]:
        acts += [{"id": "unifi:set-locate", "label": "Faire clignoter (localiser)"},
                 {"id": "unifi:unset-locate", "label": "Arrêter le clignotement"},
                 {"id": "unifi:restart", "label": "Redémarrer", "confirm": "Redémarrer cet équipement UniFi ?"}]
        if u.get("upgradable"):
            acts.append({"id": "unifi:upgrade", "label": f"Mettre à jour le firmware ({u.get('latest') or 'dernière'})",
                         "confirm": "Lancer la mise à jour du firmware ? L'équipement redémarrera."})
        if u.get("adopted") is False:
            acts.append({"id": "unifi:adopt", "label": "Adopter dans le contrôleur"})
    for m in d.get("fw_modules") or []:
        if m["can_upgrade"] and m["latest"] and m["latest"] != m["current"]:
            acts.append({"id": f"tuya:upgrade:{m['channel']}",
                         "label": f"Mettre à jour {m['module']} ({m['current']} → {m['latest']})",
                         "confirm": "Lancer la mise à jour Tuya ? L'appareil sera indisponible quelques minutes."})
    return acts


def run_action(dev_id, action):
    with LOCK:
        d = DEVICES.get(dev_id)
    if not d:
        raise RuntimeError("équipement inconnu")
    if action.startswith("unifi:"):
        c = _CLIENTS.get("unifi")
        if not c:
            raise RuntimeError("contrôleur UniFi non configuré")
        cmd = action.split(":", 1)[1]
        c.command(d["mac"], cmd)
        log(f"UniFi : « {cmd} » envoyé à {d.get('name') or d['mac']}.", "ok")
    elif action.startswith("tuya:upgrade:"):
        c = _CLIENTS.get("tuya")
        if not c:
            raise RuntimeError("compte Tuya non configuré")
        c.upgrade(d["tuya"]["gw_id"], action.rsplit(":", 1)[1])
        log(f"Tuya : mise à jour lancée pour {d.get('name') or d['tuya']['gw_id']}.", "ok")
    else:
        raise RuntimeError("action inconnue")


# ─────────────────── aide ───────────────────

HELP = {
    "tuya": """## Relier ton compte Tuya / Smart Life

Pharos Finder lit tes appareils via l'API officielle Tuya (comme Home Assistant ou tinytuya). \
Il te faut un projet développeur gratuit, relié à ton application Smart Life. Compte 10 minutes, une seule fois.

**1. Crée un compte développeur**
Va sur **platform.tuya.com** et inscris-toi (gratuit). Tu peux utiliser la même adresse e-mail que Smart Life.

**2. Crée un projet cloud**
Menu **Cloud → Development → Create Cloud Project** :
- *Project Name* : ce que tu veux (ex. « Maison »)
- *Industry* : **Smart Home** · *Development Method* : **Smart Home**
- *Data Center* : **Central Europe Data Center** si ton compte Smart Life est français. \
Il doit être le même que celui de ton compte Smart Life, sinon aucun appareil n'apparaîtra.

À l'écran suivant, garde les services proposés (au minimum **IoT Core** et **Authorization Token Management**) et valide.

**3. Relie ton application Smart Life**
Dans le projet : onglet **Devices → Link App Account → Add App Account**. Un QR code s'affiche.
Sur ton téléphone, dans Smart Life : **Moi** → icône de scan en haut à droite → scanne le QR code → confirme.
Tes appareils apparaissent alors dans l'onglet *Devices* du projet.

**4. Copie les clés**
Onglet **Overview** du projet : copie **Access ID/Client ID** et **Access Secret/Client Secret**.

**5. Dans Pharos Finder**
Bouton **Comptes** → Tuya : colle les deux clés, choisis la région **Europe** (celle du point 2), puis **Enregistrer et synchroniser**.

**Ce que tu obtiens** : le nom de chaque appareil, son type (passerelle Zigbee, prise, capteur…), \
les capteurs Zigbee/Bluetooth rattachés à chaque passerelle, les versions de firmware et, quand Tuya le permet, un bouton de mise à jour.

**En cas de problème**
- *« permission deny » ou « No permissions »* : dans le projet, onglet **Service API**, vérifie que **IoT Core** est activé.
- *Aucun appareil* : mauvaise région (point 2) ou compte Smart Life non relié (point 3).
- *« trial edition expired »* : le service IoT Core gratuit se prolonge tous les 6 mois : \
**Cloud → Cloud Services → IoT Core → Extend Trial Period** (gratuit).
- Les clés restent sur ton ordinateur (trousseau macOS, ou fichier protégé si tu coches « mémoriser » sur PC) \
et ne sont envoyées qu'au cloud Tuya.
""",
    "unifi": """## Relier ton contrôleur UniFi

Pharos Finder pilote tes équipements UniFi via ton contrôleur **UniFi Network** (console UniFi OS : \
UDM, Cloud Key, UniFi OS Server ; ou application Network installée sur un ordinateur).

1. Dans UniFi, crée de préférence un **administrateur local** dédié (*Paramètres → Administrateurs → Ajouter*, \
« Accès restreint aux administrateurs locaux »). Les comptes Ubiquiti avec double authentification ne fonctionnent pas en local.
2. Dans Pharos Finder : **Comptes → UniFi** : adresse du contrôleur (ex. `https://10.10.10.1` pour une console, \
`https://10.10.10.50:8443` pour l'application Network), identifiant, mot de passe, site (`default` en général).
3. **Enregistrer et synchroniser**.

Tu peux alors : faire clignoter un équipement pour le localiser, le redémarrer, lancer sa mise à jour de firmware, \
et adopter un équipement neuf.
""",
}


TUNNELS = {}   # id équipement -> {"port", "target"}


def ensure_tunnel(dev_id, target, port):
    """Relais local 127.0.0.1:P → [fe80::…%if]:port, pour ouvrir l'interface web d'un Pharos
    dont on ne connaît que l'adresse IPv6 link-local (les navigateurs refusent les %scope)."""
    with LOCK:
        t = TUNNELS.get(dev_id)
        if t and t["target"] == (target, port):
            return t["url"]
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    local = srv.getsockname()[1]

    def pump(a, b):
        try:
            while True:
                data = a.recv(65536)
                if not data:
                    break
                b.sendall(data)
        except OSError:
            pass
        finally:
            for s_ in (a, b):
                try:
                    s_.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            try:
                r = socket.create_connection((target, port), timeout=5)
                r.settimeout(None)
            except OSError:
                c.close()
                continue
            threading.Thread(target=pump, args=(c, r), daemon=True).start()
            threading.Thread(target=pump, args=(r, c), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    url = f"{'https' if port == 443 else 'http'}://127.0.0.1:{local}/"
    with LOCK:
        TUNNELS[dev_id] = {"target": (target, port), "url": url}
    log(f"Accès web via IPv6 : {url} → [{target}]:{port}")
    return url


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
    if iface.get("wireless") and factory:
        log(f"{iface_name} est une interface Wi-Fi : beaucoup de points d'accès bloquent l'accès à "
            "un Pharos resté sur son IP d'usine (192.168.0.254). Si rien n'est trouvé, relie le "
            "Pharos (injecteur PoE) en Ethernet au Mac, choisis cette interface, puis relance.", "warn")
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
        if JOBS.get("scan", {}).get("stop"):
            log("Recherche interrompue.", "warn")
            break
        alias = None
        if needs_alias:
            if not IS_ROOT:
                log(f"Plage {net} sautée : adresse temporaire impossible sans droits admin", "warn")
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
        targets = [h for h in hosts if str(h) not in local_ips and str(h) != alias]
        if needs_alias and not full:
            # Peu d'adresses : sonde plus patiente (ping 1 s + HTTPS/HTTP), deux passes, car le
            # premier ARP via une adresse toute neuve (Wi-Fi surtout) est souvent perdu.
            alive = set()
            for _ in range(2):
                alive |= set(sweep([h for h in targets if str(h) not in alive], probe=probe_host))
                if alive:
                    break
        else:
            alive = set(sweep(targets))
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
    if not JOBS.get("scan", {}).get("stop"):
        discover_mdns(iface)
    if not JOBS.get("scan", {}).get("stop"):
        discover_vendors(iface)
    for vendor, job in (("tuya", job_tuya_sync), ("unifi", job_unifi_sync)):
        if vendor in _CLIENTS and not JOBS.get("scan", {}).get("stop"):
            try:
                job()
            except Exception as e:  # noqa: BLE001
                log(str(e), "warn")
    if not JOBS.get("scan", {}).get("stop"):
        discover_ipv6(iface)
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


# ─────────────────────────── AES-128 minimal (stdlib seulement) ───────────────────────────
# Sert uniquement à lire les annonces locales Tuya (clé publique, documentée par tinytuya).

def _aes_tables():
    sbox, inv = [0] * 256, [0] * 256
    p = q = 1
    while True:  # génération classique via le générateur 3 de GF(2^8)
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        x = (x ^ 0x63) & 0xFF
        sbox[p] = x
        inv[x] = p
        if p == 1:
            break
    sbox[0], inv[0x63] = 0x63, 0
    return sbox, inv


_SBOX, _INV_SBOX = _aes_tables()


def _xt(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a, b = _xt(a), b >> 1
    return r


def _aes_expand(key):
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [_SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xt(rcon)
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [sum(w[r * 4:r * 4 + 4], []) for r in range(11)]


def aes_encrypt_block(rk, block):
    s = [b ^ k for b, k in zip(block, rk[0])]
    for r in range(1, 11):
        s = [_SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]  # ShiftRows
        if r != 10:
            m = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                m += [_mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3],
                      a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3],
                      a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3),
                      _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)]
            s = m
        s = [b ^ k for b, k in zip(s, rk[r])]
    return bytes(s)


def aes_decrypt_block(rk, block):
    s = [b ^ k for b, k in zip(block, rk[10])]
    for r in range(9, -1, -1):
        s = [s[(i - 4 * (i % 4)) % 16] for i in range(16)]  # InvShiftRows
        s = [_INV_SBOX[b] for b in s]
        s = [b ^ k for b, k in zip(s, rk[r])]
        if r:
            m = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                m += [_mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9),
                      _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13),
                      _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11),
                      _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)]
            s = m
    return bytes(s)


def aes_ecb_decrypt(key, data):
    rk = _aes_expand(key)
    out = b"".join(aes_decrypt_block(rk, data[i:i + 16]) for i in range(0, len(data) - len(data) % 16, 16))
    pad = out[-1] if out else 0
    return out[:-pad] if 1 <= pad <= 16 and out.endswith(bytes([pad]) * pad) else out


def aes_gcm_decrypt_unverified(key, iv, data):
    """Déchiffrement GCM sans vérifier l'étiquette (lecture d'annonce, pas de sécurité en jeu)."""
    rk = _aes_expand(key)
    out = bytearray()
    for i in range(0, len(data), 16):
        ctr = iv + (i // 16 + 2).to_bytes(4, "big")
        ks = aes_encrypt_block(rk, ctr)
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], ks))
    return bytes(out)


# ─────────────────────────── Tuya / Smart Life ───────────────────────────
# Les appareils Tuya diffusent leur présence en broadcast (documenté par tinytuya) :
#   UDP 6666 : protocole 3.1, JSON en clair ; UDP 6667 : 3.3/3.4, AES-128-ECB, clé
#   md5("yGAdlopoPVldABfn") ; UDP 7000 : 3.5, AES-GCM avec la même clé.

import hashlib  # noqa: E402

TUYA_UDP_KEY = hashlib.md5(b"yGAdlopoPVldABfn").digest()
TUYA_PORTS = (6666, 6667, 7000)


def _json_in(raw):
    txt = raw.decode("utf-8", "ignore")
    a, b = txt.find("{"), txt.rfind("}")
    if a < 0 or b <= a:
        return None
    try:
        return json.loads(txt[a:b + 1])
    except ValueError:
        return None


def parse_tuya_broadcast(data, port):
    """Annonce Tuya → dict (ip, gwId, productKey, version…) ou None."""
    if data[:4] == b"\x00\x00\x55\xaa" and data[-4:] == b"\x00\x00\xaa\x55" and len(data) > 28:
        body = data[16:-8]  # après préfixe, seq, cmd, longueur
        if port == 6666:
            return _json_in(body)
        for chunk in (body[4:], body):  # le plus souvent précédé d'un code retour de 4 octets
            if len(chunk) >= 16:
                obj = _json_in(aes_ecb_decrypt(TUYA_UDP_KEY, chunk[:len(chunk) - len(chunk) % 16]))
                if obj:
                    return obj
        return None
    if data[:4] == b"\x00\x00\x66\x99" and data[-4:] == b"\x00\x00\x99\x66" and len(data) > 52:
        # 6699 | 2 octets | seq | cmd | longueur | iv(12) | chiffré | tag(16) | 9966
        iv, enc = data[18:30], data[30:-20]
        obj = _json_in(aes_gcm_decrypt_unverified(TUYA_UDP_KEY, iv, enc))
        if obj is None:
            obj = {}
        obj.setdefault("version", "3.5")
        return obj
    return None


_TUYA_SEEN = set()


def handle_tuya(data, sender_ip, port):
    obj = parse_tuya_broadcast(data, port)
    if obj is None:
        return
    ip = obj.get("ip") or sender_ip
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        ip = sender_ip
    info = {"gw_id": obj.get("gwId") or obj.get("devId"), "product_key": obj.get("productKey"),
            "version": str(obj.get("version") or ("3.1" if port == 6666 else "3.3"))}
    mac = next((e["mac"] for e in arp_table() if e["ip"] == ip), None) if ip not in {k[0] for k in _TUYA_SEEN} else None
    d = upsert(mac=mac, ip=ip, source="Tuya", tuya=info, model=f"Tuya v{info['version']}",
               title=f"Smart Life / Tuya · {info['gw_id'] or 'ID inconnu'}")
    key = (ip, info["gw_id"])
    if d and key not in _TUYA_SEEN:
        _TUYA_SEEN.add(key)
        log(f"Tuya : appareil {info['gw_id'] or '?'} (v{info['version']}"
            f"{', produit ' + info['product_key'] if info['product_key'] else ''}) en {ip}", "ok")


def tuya_listener():
    """Écoute permanente des annonces Tuya (sans droits admin, Mac/PC/Linux)."""
    socks = {}
    for port in TUYA_PORTS:
        s_ = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s_.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                s_.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        try:
            s_.bind(("", port))
            socks[s_] = port
        except OSError as e:
            log(f"Port Tuya {port} indisponible ({e}) : annonces Tuya de ce port ignorées.", "warn")
    import select
    while socks:
        ready, _, _ = select.select(list(socks), [], [], 2)
        for s_ in ready:
            try:
                data, addr = s_.recvfrom(4096)
                handle_tuya(data, addr[0], socks[s_])
            except Exception as e:  # noqa: BLE001
                log(f"Annonce Tuya illisible : {e}", "warn")


# ─────────────────────────── mDNS / Bonjour ───────────────────────────

MDNS_SERVICES = ("_amzn-wplay._tcp", "_amzn-alexa._tcp", "_spotify-connect._tcp", "_googlecast._tcp",
                 "_airplay._tcp", "_raop._tcp", "_hap._tcp", "_companion-link._tcp", "_http._tcp",
                 "_ipp._tcp", "_printer._tcp", "_smb._tcp", "_device-info._tcp", "_matter._tcp",
                 "_sonos._tcp", "_workstation._tcp", "_qdiscover._tcp")


def _dns_name(msg, p):
    labels, jumped, end = [], False, p
    for _ in range(64):
        if p >= len(msg):
            break
        n = msg[p]
        if n == 0:
            p += 1
            break
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = p + 2
            p, jumped = ((n & 0x3F) << 8) | msg[p + 1], True
            continue
        labels.append(msg[p + 1:p + 1 + n].decode("utf-8", "ignore"))
        p += 1 + n
    return ".".join(labels), (end if jumped else p)


def mdns_query_packet(services=MDNS_SERVICES):
    q = b"".join(b"".join(bytes([len(x)]) + x.encode() for x in (sv + ".local").split(".")) + b"\x00"
                 + struct.pack("!HH", 12, 0x8001) for sv in services)  # PTR, IN + réponse unicast
    return struct.pack("!HHHHHH", 0, 0, len(services), 0, 0, 0) + q


def parse_mdns(msg):
    """Réponse mDNS → {"hosts": {ip: nom}, "instances": [(service, instance)], "services": set}"""
    out = {"hosts": {}, "instances": [], "services": set()}
    if len(msg) < 12:
        return out
    qd, an, ns, ar = struct.unpack("!HHHH", msg[4:12])
    p = 12
    for _ in range(qd):
        _, p = _dns_name(msg, p)
        p += 4
    for _ in range(an + ns + ar):
        name, p = _dns_name(msg, p)
        if p + 10 > len(msg):
            break
        rtype, _, _, rdlen = struct.unpack("!HHIH", msg[p:p + 10])
        rd = p + 10
        p = rd + rdlen
        if rtype == 12:  # PTR
            target, _ = _dns_name(msg, rd)
            svc = name.replace(".local", "")
            if svc.startswith("_") and not svc.startswith("_services"):
                inst = target.split("._")[0]
                out["instances"].append((svc, inst))
                out["services"].add(svc)
        elif rtype == 1 and rdlen == 4:  # A
            out["hosts"][socket.inet_ntoa(msg[rd:rd + 4])] = name.replace(".local", "")
    return out


def discover_mdns(iface, wait=3.0):
    """Interroge Bonjour : noms d'appareils (Fire TV, Echo/Spotify, AirPlay, imprimantes…)."""
    ips = [a["ip"] for a in iface["ipv4"] if not a["ip"].startswith("169.254.")]
    if not ips:
        return
    log(f"Recherche des noms Bonjour/mDNS sur {iface['name']}…")
    s_ = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s_.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ips[0]))
        s_.bind((ips[0], 0))
        pkt = mdns_query_packet()
        for _ in range(2):
            s_.sendto(pkt, ("224.0.0.251", 5353))
            time.sleep(0.3)
        s_.settimeout(0.5)
        found, end = {}, time.time() + wait
        while time.time() < end:
            try:
                data, addr = s_.recvfrom(9000)
            except socket.timeout:
                continue
            r = parse_mdns(data)
            e = found.setdefault(addr[0], {"names": [], "services": set(), "host": None})
            e["services"] |= r["services"]
            e["names"] += [inst for _, inst in r["instances"] if inst not in e["names"]]
            e["host"] = e["host"] or r["hosts"].get(addr[0])
    except OSError as e:
        log(f"mDNS indisponible : {e}", "warn")
        return
    finally:
        s_.close()
    macs = {e["ip"]: e["mac"] for e in arp_table()}
    own = all_local_ips()
    found = {ip: e for ip, e in found.items() if ip not in own}
    for ip, e in found.items():
        # « AA11BB22@Salon » (AirPlay audio) → « Salon »
        names = [n.split("@", 1)[-1] for n in e["names"]]
        name = next((n for n in names if n), None) or e["host"]
        d = upsert(mac=macs.get(ip), ip=ip, source="mDNS", name=name, services=sorted(e["services"]))
        if d and d["kind"] == "amazon" and d.get("fingerprinted"):
            d["model"] = amazon_model(d["ports"], d["services"])
    log(f"mDNS : {len(found)} appareil(s) nommé(s).", "ok" if found else "info")


# ─────────────────────────── Amazon (Echo, Fire TV…) ───────────────────────────

AMAZON_PORTS = (4070, 5555, 8009, 55442, 55443)


def amazon_model(ports, services):
    services = services or []
    if any(sv.startswith("_amzn-wplay") for sv in services) or 5555 in ports:
        return "Fire TV"
    if 55443 in ports or 55442 in ports or 4070 in ports or "_spotify-connect._tcp" in services \
            or any(sv.startswith("_amzn-alexa") for sv in services):
        return "Echo"
    return "Amazon"


# ─────────────── annonces CDP / LLDP (PharOS : CDP toutes les 60 s) ───────────────

CDP_DST = bytes.fromhex("01000ccccccc")


def _cdp_addresses(v):
    ips, p = [], 4
    for _ in range(struct.unpack("!I", v[:4])[0] if len(v) >= 4 else 0):
        if p + 2 > len(v):
            break
        ptype, plen = v[p], v[p + 1]
        proto = v[p + 2:p + 2 + plen]
        p += 2 + plen
        alen = struct.unpack("!H", v[p:p + 2])[0] if p + 2 <= len(v) else 0
        addr = v[p + 2:p + 2 + alen]
        p += 2 + alen
        if ptype == 1 and proto == b"\xcc" and alen == 4:
            ips.append(socket.inet_ntoa(addr))
    return ips


def parse_discovery(frame):
    """Annonce CDP ou LLDP → {mac, ip, name, platform, firmware, proto} (ou None)."""
    if len(frame) < 22:
        return None
    src = ":".join(f"{b:02x}" for b in frame[6:12])
    txt = lambda b: b.decode("utf-8", "ignore").strip().strip("\x00")  # noqa: E731
    info = {"mac": src, "ip": None, "name": None, "platform": None, "firmware": None}
    etype = struct.unpack("!H", frame[12:14])[0]
    if frame[:6] == CDP_DST and etype <= 1500 and frame[14:17] == b"\xaa\xaa\x03" \
            and frame[17:20] == b"\x00\x00\x0c" and frame[20:22] == b"\x20\x00":
        info["proto"] = "CDP"
        p, cdp = 4, frame[22:]
        while p + 4 <= len(cdp):
            t, ln = struct.unpack("!HH", cdp[p:p + 4])
            if ln < 4:
                break
            v = cdp[p + 4:p + ln]
            p += ln
            if t == 0x01:
                info["name"] = txt(v)
            elif t in (0x02, 0x16) and not info["ip"]:
                ips = _cdp_addresses(v)
                info["ip"] = ips[0] if ips else None
            elif t == 0x05:
                info["firmware"] = txt(v)
            elif t == 0x06:
                info["platform"] = txt(v)
        return info
    if etype == 0x88CC:
        info["proto"] = "LLDP"
        p = 14
        while p + 2 <= len(frame):
            h = struct.unpack("!H", frame[p:p + 2])[0]
            t, ln = h >> 9, h & 0x1FF
            v = frame[p + 2:p + 2 + ln]
            p += 2 + ln
            if t == 0:
                break
            if t == 5:
                info["name"] = txt(v)
            elif t == 6:
                info["platform"] = txt(v)
            elif t == 8 and len(v) >= 6 and v[1] == 1 and not info["ip"]:
                info["ip"] = socket.inet_ntoa(v[2:6])
        return info
    return None


ANNOUNCED = set()


def handle_discovery_frame(frame, iface_name):
    info = parse_discovery(frame)
    if not info:
        return
    ip = info["ip"] if info["ip"] and info["ip"] != "0.0.0.0" else None
    platform = info["platform"] or ""
    model = PHAROS_MODEL_RE.search(platform) or PHAROS_MODEL_RE.search(info["name"] or "")
    pharos = bool(model) and "tp-link" in platform.lower()
    d = upsert(mac=info["mac"], ip=ip, source=info["proto"], iface=iface_name,
               model=model.group(1).upper() if model else None, title=platform or info["name"],
               firmware=info["firmware"], announced=info["proto"], pharos_hint=pharos or None)
    key = (info["mac"], ip)
    if d and key not in ANNOUNCED:
        ANNOUNCED.add(key)
        fw = f", firmware {info['firmware']}" if info["firmware"] else ""
        where = ip or "sans IPv4"
        log(f"{info['proto']} : {platform or info['name'] or info['mac']} ({info['mac']}{fw}) annonce {where} "
            f"sur {iface_name}", "ok" if d["kind"] == "pharos" else "info")
        if ip and d["kind"] != "other" and not d.get("fingerprinted"):
            threading.Thread(target=_fingerprint_if_reachable, args=(d["id"],), daemon=True).start()


def _fingerprint_if_reachable(dev_id):
    with LOCK:
        d = DEVICES.get(dev_id)
        ip = d["ip"] if d else None
    if ip and any(ipaddress.IPv4Address(ip) in n for i in list_interfaces() for n in iface_networks(i)):
        fingerprint(dev_id)


ANNOUNCE_FILTER = "ether dst 01:00:0c:cc:cc:cc or ether proto 0x88cc"
_SNIFFERS = {}   # interface -> Popen


def announcement_sniffer():
    """Écoute en permanence les annonces CDP/LLDP sur chaque interface active : un Pharos
    configuré est trouvé en moins d'une minute, quelle que soit sa plage IP, sans rien faire."""
    if not IS_ROOT or IS_WIN or not shutil_which("tcpdump"):
        return
    while True:
        try:
            active = {i["name"] for i in list_interfaces() if i["active"]}
            for name, proc in list(_SNIFFERS.items()):
                if name not in active or proc.poll() is not None:
                    if proc.poll() is None:
                        proc.terminate()
                    del _SNIFFERS[name]
            for name in active - set(_SNIFFERS):
                proc = subprocess.Popen(["tcpdump", "-i", name, "-U", "-s", "0", "-w", "-", ANNOUNCE_FILTER],
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
                _SNIFFERS[name] = proc

                def reader(p=proc, n=name):
                    for frame in iter_pcap(p.stdout):
                        try:
                            handle_discovery_frame(frame, n)
                        except Exception as e:  # noqa: BLE001
                            log(f"Annonce illisible sur {n} : {e}", "warn")

                threading.Thread(target=reader, daemon=True).start()
        except Exception as e:  # noqa: BLE001
            log(f"Écoute des annonces : {e}", "warn")
        time.sleep(10)


def stop_sniffers():
    for proc in _SNIFFERS.values():
        if proc.poll() is None:
            proc.terminate()


TDP_PORTS = {20001, 20002}


def is_lan_ip(ip):
    a = ipaddress.IPv4Address(ip)
    return (a.is_private or a.is_link_local) and not a.is_multicast


def parse_ipv4_packet(pkt, src_mac=None):
    """Paquet IPv4 brut → (mac|None, ip|None, tdp). Lit l'adresse MAC dans les requêtes DHCP."""
    if len(pkt) < 20 or pkt[0] >> 4 != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    src = socket.inet_ntoa(pkt[12:16])
    mac, tdp = src_mac, False
    if pkt[9] == 17 and len(pkt) >= ihl + 8:
        sport, dport = struct.unpack("!HH", pkt[ihl:ihl + 4])
        tdp = bool({sport, dport} & TDP_PORTS)
        bootp = pkt[ihl + 8:]
        if {sport, dport} & {67, 68} and len(bootp) >= 34 and bootp[0] == 1:
            mac = ":".join(f"{b:02x}" for b in bootp[28:34])
    ip = None if src in ("0.0.0.0", "255.255.255.255") else src
    if not mac and not ip:
        return None
    return mac, ip, tdp


def parse_eth_frame(frame):
    """Trame Ethernet brute → (mac, ip|None, tdp) pour ARP et IPv4."""
    if len(frame) < 14:
        return None
    src = ":".join(f"{b:02x}" for b in frame[6:12])
    etype, off = struct.unpack("!H", frame[12:14])[0], 14
    if etype == 0x8100 and len(frame) >= 18:  # VLAN
        etype, off = struct.unpack("!H", frame[16:18])[0], 18
    if is_multicast_mac(src):
        return None
    if etype == 0x0806 and len(frame) >= off + 28:
        ip = socket.inet_ntoa(frame[off + 14:off + 18])
        return src, (None if ip == "0.0.0.0" else ip), False
    if etype == 0x0800:
        p = parse_ipv4_packet(frame[off:], src)
        return (src,) + p[1:] if p else (src, None, False)
    # IPv6 (ND/MLD), LLDP… : un Pharos qui démarre s'annonce souvent ainsi avant tout ARP.
    return src, None, False


def iter_pcap(stream):
    """Lit un flux pcap (tcpdump -w -) et renvoie les trames Ethernet une par une."""
    head = stream.read(24)
    if len(head) < 24:
        return
    endian = "<" if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    while True:
        rec = stream.read(16)
        if len(rec) < 16:
            return
        incl = struct.unpack(endian + "IIII", rec)[2]
        frame = stream.read(incl)
        if len(frame) < incl:
            return
        yield frame


def _listen_tcpdump(iface, stop):
    cmd = ["tcpdump", "-i", iface["name"], "-U", "-s", "0", "-w", "-"]
    if iface["mac"]:
        cmd += ["not", "ether", "src", iface["mac"]]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    with LOCK:
        JOBS["listen"]["proc"] = proc

    def _watchdog():  # read() bloque tant qu'aucune trame n'arrive
        while proc.poll() is None and not stop():
            time.sleep(0.3)
        if proc.poll() is None:
            proc.terminate()

    threading.Thread(target=_watchdog, daemon=True).start()
    try:
        for frame in iter_pcap(proc.stdout):
            if stop():
                break
            handle_discovery_frame(frame, iface["name"])
            yield parse_eth_frame(frame)
    finally:
        if proc.poll() is None:
            proc.terminate()


def _listen_af_packet(iface, stop):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((iface["name"], 0))
    s.settimeout(0.5)
    try:
        while not stop():
            try:
                frame = s.recv(65535)
            except socket.timeout:
                yield None
                continue
            handle_discovery_frame(frame, iface["name"])
            p = parse_eth_frame(frame)
            yield p if p and p[0] != iface["mac"] else None
    finally:
        s.close()


def _listen_windows(iface, stop):
    if not iface["ipv4"]:
        raise RuntimeError("Windows a besoin d'une adresse IPv4 sur l'interface pour écouter "
                           "(même 169.254.x) : vérifie que le câble est branché.")
    own = {a["ip"] for a in iface["ipv4"]}
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind((iface["ipv4"][0]["ip"], 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    s.settimeout(0.5)
    try:
        while not stop():
            try:
                pkt = s.recv(65535)
            except socket.timeout:
                yield None
                continue
            except OSError:
                continue
            p = parse_ipv4_packet(pkt)
            yield p if p and p[1] not in own else None
    finally:
        try:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except OSError:
            pass
        s.close()


def listen_backend():
    if IS_WIN:
        return _listen_windows, "socket brute Windows (IPv4 : DHCP, TDP, trafic IP)"
    if IS_LINUX and not shutil_which("tcpdump"):
        return _listen_af_packet, "socket AF_PACKET"
    return _listen_tcpdump, "tcpdump"


def shutil_which(name):
    import shutil
    return shutil.which(name, path=os.environ.get("PATH", "") + os.pathsep + "/usr/sbin:/sbin")


TDP_PCAP = os.path.join("C:\\Windows\\Temp" if IS_WIN else "/tmp", "PharosFinder-tdp.pcap")


def start_tdp_capture(iface_name):
    """Enregistre les trames TDP (UDP 20001/20002) brutes dans un pcap, pour étudier la
    découverte de Pharos Control sans en inventer le format."""
    if IS_WIN or not shutil_which("tcpdump"):
        return None
    try:
        os.remove(TDP_PCAP)
    except OSError:
        pass
    try:
        # TDP + toute trame émise par une MAC TP-Link (LLDP, IPv6, DHCP… : on veut tout voir).
        ouis = " or ".join(f"(ether[6:2] = 0x{o[0:2]}{o[3:5]} and ether[8] = 0x{o[6:8]})"
                           for o in sorted(TPLINK_OUIS))
        return subprocess.Popen(["tcpdump", "-i", iface_name, "-U", "-s", "0", "-w", TDP_PCAP,
                                 f"udp port 20001 or udp port 20002 or {ouis}"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        return None


def stop_tdp_capture(proc):
    if not proc:
        return
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    try:
        os.chmod(TDP_PCAP, 0o644)
        size = os.path.getsize(TDP_PCAP)
    except OSError:
        return
    if size > 24:  # plus que l'en-tête pcap : du trafic TDP a été vu
        log(f"Trafic TDP / TP-Link enregistré : {TDP_PCAP} ({size} octets).", "ok")


def job_listen(iface_name, seconds):
    if not IS_ROOT:
        raise RuntimeError("l'écoute passive nécessite les droits administrateur")
    iface = get_iface(iface_name)
    if not iface:
        raise RuntimeError(f"interface {iface_name} introuvable")
    backend, label = listen_backend()
    deadline = time.time() + seconds

    def stop():
        return time.time() >= deadline or JOBS.get("listen", {}).get("stop")

    log(f"Écoute passive sur {iface_name} pendant {seconds} s ({label}) — débranche/rebranche "
        "l'alimentation PoE du Pharos maintenant pour capter ses annonces.", "ok")
    tdp_cap = start_tdp_capture(iface_name)
    seen, count = {}, 0
    for p in backend(iface, stop):
        if stop():
            break
        if p is None:
            continue
        count += 1
        mac, ip, tdp = p
        if ip and (ip.startswith("0.") or not (tdp or is_lan_ip(ip))):
            ip = None  # adresse Internet routée par la passerelle : ce n'est pas son IP à elle
        if not mac and not ip:
            continue
        first = (mac, ip) not in seen
        seen[(mac, ip)] = True
        d = upsert(mac=mac, ip=ip, source="écoute", iface=iface_name, tdp=tdp or None)
        if d and first:
            note = " · trafic TDP (port 20002)" if tdp else ""
            log(f"Vu {mac or 'MAC ?'} ({d['vendor'] or 'fabricant ?'}) → {ip or 'sans IP'}{note}",
                "ok" if d["kind"] != "other" else "info")
    macs = {m for (m, _) in seen if m}
    ips_seen = {i for (_, i) in seen if i}
    log(f"Écoute terminée : {count} trame(s), {len(seen)} émetteur(s) distinct(s).", "ok")
    stop_tdp_capture(tdp_cap)
    if count == 0:
        log("Aucune trame reçue : lien inactif, mauvais câble, ou port isolé/VLAN différent.", "warn")
        if IS_WIN:
            log("Sous Windows, le pare-feu peut bloquer l'écoute : autorise Pharos Finder "
                "sur les réseaux privés et publics si Windows le demande.", "warn")
    # Complète les MAC manquantes (Windows ne voit que l'IP) avec la table ARP.
    for e in arp_table():
        if e["ip"] in ips_seen:
            upsert(mac=e["mac"], ip=e["ip"], source="écoute", iface=iface_name)
    with LOCK:
        ids = [d["id"] for d in DEVICES.values()
               if (d["mac"] in macs or d["ip"] in ips_seen) and d["ip"] and not d["ip"].startswith("169.254.")]
    nets = iface_networks(get_iface(iface_name) or iface)
    reachable = [i for i in ids if any(ipaddress.IPv4Address(DEVICES[i]["ip"]) in n for n in nets)]
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
        announced = DEVICES[dev_id].get("announced")
    log(f"{ip} {'joignable' if ok else 'ne répond toujours pas'}", "ok" if ok else "warn")
    if not ok and announced:
        log(f"Il s'annonce en {announced} avec {ip} mais ignore les requêtes du câble : sa gestion est "
            "verrouillée côté LAN (VLAN de gestion activé, ou contrôle d'accès PharOS). Relie-le "
            "directement au Mac et indique le numéro de VLAN, ou fais un reset.", "warn")


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
    if IS_WIN:
        # explorer.exe transmet l'URL au shell de l'utilisateur : le navigateur ne tourne
        # pas en administrateur même si le moteur, lui, l'est.
        subprocess.Popen(["explorer.exe", url], creationflags=NO_WINDOW)
        return
    r = as_user(["open", url]) if IS_MAC else as_user(["xdg-open", url])
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "ouverture impossible")


def ssh_command(ip, user):
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", user or ""):
        raise RuntimeError("nom d'utilisateur invalide")
    if not re.fullmatch(r"(\d{1,3}(\.\d{1,3}){3})|(fe80:[0-9a-fA-F:]+%[A-Za-z0-9]+)", ip or ""):
        raise RuntimeError("adresse invalide")
    opts = ["-o", "StrictHostKeyChecking=accept-new",
            "-o", "KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
            "-o", "HostKeyAlgorithms=+ssh-rsa"]
    if not IS_WIN:  # OpenSSH 7.x livré avec Windows 10 ne connaît pas cette option
        opts += ["-o", "PubkeyAcceptedAlgorithms=+ssh-rsa"]
    return ["ssh"] + opts + [f"{user}@{ip}"]


def open_ssh(ip, user):
    cmd = ssh_command(ip, user)
    line = " ".join(cmd)
    if IS_WIN:
        if not shutil_which("ssh"):
            raise RuntimeError("client SSH introuvable : active « Client OpenSSH » dans "
                               "Paramètres → Applications → Fonctionnalités facultatives.")
        subprocess.Popen(["cmd.exe", "/k"] + cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)
        return
    if IS_MAC:
        script = f'tell application "Terminal"\nactivate\ndo script "{line}"\nend tell'
        r = as_user(["osascript", "-e", script])
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or "Terminal inaccessible")
        return
    for term in (["x-terminal-emulator", "-e"], ["gnome-terminal", "--"], ["konsole", "-e"], ["xterm", "-e"]):
        if shutil_which(term[0]):
            try:
                subprocess.Popen((["sudo", "-u", SUDO_USER] if IS_ROOT and SUDO_USER else []) + term + cmd)
                return
            except OSError:
                pass
    raise RuntimeError(f"ouvre un terminal et lance : {line}")


def snapshot():
    ifaces = list_interfaces()
    nets = [(i["name"], n) for i in ifaces for n in iface_networks(i) if not n.network_address.is_link_local]
    with LOCK:
        devs = []
        for d in DEVICES.values():
            c = dict(d)
            c["actions"] = device_actions(d)
            c["conflict"] = bool(d["ip"]) and any(o is not d and o["ip"] == d["ip"] and o["mac"]
                                                  for o in DEVICES.values())
            c["in_range"] = bool(d["ip"]) and not d["ip"].startswith("169.254.") and \
                any(ipaddress.IPv4Address(d["ip"]) in n for _, n in nets)
            devs.append(c)
        order = {k: i for i, k in enumerate(KINDS)}
        devs.sort(key=lambda x: (order[x["kind"]], tuple(int(p) for p in (x["ip"] or "255.255.255.255").split("."))))
        return {
            "version": VERSION, "root": IS_ROOT, "mac_os": IS_MAC, "platform": PLATFORM,
            "interfaces": ifaces, "devices": devs, "log": LOG[-200:],
            "jobs": {k: {"label": v["label"], "elapsed": int(time.time() - v["started"])} for k, v in JOBS.items()},
            "aliases": list(ALIASES),
            "integrations": {k: dict(v) for k, v in INTEGRATIONS.items()},
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
        if u.path == "/api/help":
            if not self._authorized():
                return self._send(403, {"error": "jeton invalide"})
            return self._send(200, HELP)
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
            if not IS_ROOT:
                raise RuntimeError("l'écoute passive nécessite les droits administrateur")
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
        elif path == "/api/account":
            configure_account(b.get("vendor"), b, persist=bool(b.get("persist")))
            start_job(f"{b['vendor']}_sync", f"Synchronisation {b['vendor']}",
                      job_tuya_sync if b["vendor"] == "tuya" else job_unifi_sync)
        elif path == "/api/account/forget":
            forget_account(b.get("vendor"))
        elif path == "/api/sync":
            v = b.get("vendor")
            start_job(f"{v}_sync", f"Synchronisation {v}", job_tuya_sync if v == "tuya" else job_unifi_sync)
        elif path == "/api/action":
            start_job("action", "Action", run_action, b["id"], b["action"])
        elif path == "/api/vlan":
            vl = [int(v) for v in re.split(r"[,\s]+", str(b.get("vlans", ""))) if v.strip()] or COMMON_VLANS
            vl = [v for v in vl if 1 <= v <= 4094][:64]
            start_job("vlan", "Test des VLAN", job_vlan_probe, b["iface"], str(ipaddress.IPv4Address(b["ip"])), vl)
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
                stop_sniffers()
                os._exit(0)
            threading.Thread(target=_bye, daemon=True).start()
        elif path == "/api/clear":
            with LOCK:
                DEVICES.clear()
            log("Liste vidée.")
        else:
            raise RuntimeError("action inconnue")
        return {"ok": True}


def pid_alive(pid):
    if IS_WIN:
        # os.kill(pid, 0) enverrait un Ctrl+C sous Windows : on interroge le processus.
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
        if not h:
            return False
        try:
            return k32.WaitForSingleObject(h, 0) == 0x102  # WAIT_TIMEOUT : toujours vivant
        finally:
            k32.CloseHandle(h)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def relaunch_elevated_windows():
    """Relance le programme via l'invite UAC. Renvoie True si l'instance admin a démarré."""
    import ctypes
    argv = sys.argv[1:] if getattr(sys, "frozen", False) else [os.path.abspath(sys.argv[0])] + sys.argv[1:]
    params = subprocess.list2cmdline(argv + ["--elevated"])
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    return rc > 32


_CONSOLE_HANDLER = None


def install_windows_close_handler():
    """Fermeture de la fenêtre console : on retire les alias avant que Windows ne tue le processus."""
    global _CONSOLE_HANDLER
    import ctypes
    from ctypes import wintypes

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
    def handler(event):
        cleanup_aliases()
        if event in (0, 1):  # Ctrl+C / Ctrl+Break : on quitte proprement
            os._exit(0)
        return False

    _CONSOLE_HANDLER = handler
    ctypes.windll.kernel32.SetConsoleCtrlHandler(handler, True)


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # console Windows en cp850/cp1252
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="Pharos Finder — découverte des équipements TP-Link PharOS")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--token", help="jeton fixe (utilisé par l'app macOS)")
    ap.add_argument("--parent-pid", type=int, help="s'arrête quand ce processus disparaît")
    ap.add_argument("--no-elevate", action="store_true", help="Windows : ne pas demander les droits admin")
    ap.add_argument("--elevated", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()

    if IS_WIN and not IS_ROOT and not args.no_elevate and not args.elevated:
        print("Pharos Finder demande les droits administrateur (adresses temporaires, écoute)…")
        if relaunch_elevated_windows():
            return
        print("Droits refusés : lancement en mode limité.")

    global TOKEN
    if args.token:
        TOKEN = args.token
    if args.parent_pid:
        def _watch_parent(pid):
            while True:
                time.sleep(2)
                if not pid_alive(pid):
                    log("Application fermée : arrêt du moteur.")
                    cleanup_aliases()
                    stop_sniffers()
                    os._exit(0)
        threading.Thread(target=_watch_parent, args=(args.parent_pid,), daemon=True).start()

    if not IS_ROOT:
        print("⚠️  Lancé sans droits administrateur : balayage OK, mais pas d'adresse temporaire "
              "ni d'écoute passive.")

    atexit.register(cleanup_aliases)
    atexit.register(stop_sniffers)
    atexit.register(cleanup_vlans)
    threading.Thread(target=announcement_sniffer, daemon=True).start()
    threading.Thread(target=tuya_listener, daemon=True).start()
    load_accounts()

    def _sig(*_):
        cleanup_aliases()
        stop_sniffers()
        os._exit(0)

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)
    for name in ("SIGHUP", "SIGBREAK"):  # fenêtre Terminal fermée / Ctrl+Break
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _sig)
    if IS_WIN:
        install_windows_close_handler()

    try:
        srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    except OSError:
        if args.token:  # l'app impose le port : on ne le change pas en silence
            raise
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    url = f"http://127.0.0.1:{port}/?t={TOKEN}"
    print(f"\n  Pharos Finder {VERSION} ({PLATFORM})\n  Interface : {url}\n"
          "  Garde cette fenêtre ouverte. Ctrl+C ou fermeture = arrêt (les adresses temporaires "
          "sont retirées).\n")
    log("Pharos Finder prêt. Choisis l'interface reliée au Pharos puis « Rechercher ».", "ok")
    if not args.no_browser:
        def _open():
            try:
                open_url(url)
            except Exception as e:  # noqa: BLE001
                print(f"Ouvre ce lien dans ton navigateur : {url} ({e})")
        threading.Timer(0.6, _open).start()
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
select,input[type=text],input[type=password],input[type=number]{font:inherit;color:var(--text);background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:5px 8px}
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
.dot.pharos{background:var(--pharos)} .dot.tplink{background:var(--tplink)} .dot.tuya{background:#f97316} .dot.amazon{background:#6366f1} .dot.unifi{background:#0ea5e9} .dot.netgear{background:#7c3aed} .dot.qnap{background:#0891b2}
.tag.upd{color:var(--ok);border-color:currentColor}
#modal{position:fixed;inset:0;background:rgba(0,0,0,.45);display:none;align-items:center;justify-content:center;z-index:10}
#modal .box{background:var(--panel);border:1px solid var(--line);border-radius:10px;width:min(760px,94vw);max-height:90vh;overflow:auto;padding:18px}
#modal .tabs{display:flex;gap:6px;margin-bottom:12px}
#modal .tabs button.on{background:var(--sel);color:var(--accent);font-weight:600}
#modal label{display:block;margin:8px 0 3px;color:var(--muted)}
#modal input[type=text],#modal input[type=password],#modal select{width:100%}
.help{border-top:1px solid var(--line);margin-top:14px;padding-top:6px;line-height:1.5}
.help h2{font-size:15px}.help code{font-family:var(--mono);background:var(--panel2);padding:0 3px;border-radius:3px}
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
  <button id="btnAccounts" title="Relier Tuya / Smart Life et le contrôleur UniFi">Comptes</button>
  <button class="danger" id="btnQuit" title="Arrête le moteur et retire les adresses temporaires">Quitter</button>
</header>

<div class="toolbar">
  <select id="iface" title="Interface reliée au Pharos"></select>
  <label class="chk" title="Ajoute un alias temporaire pour sonder 192.168.0.x (IP d'usine PharOS : .254) et 192.168.1.x"><input type="checkbox" id="factory" checked> Plages d'usine</label>
  <label class="chk" title="Balaye les 254 adresses des plages d'usine au lieu des seules adresses probables"><input type="checkbox" id="full"> Balayage complet</label>
  <input type="text" id="extra" placeholder="Autres plages : 10.0.0.0/24…" style="width:190px">
  <button class="primary" id="btnScan">Rechercher</button>
  <button id="btnListen" title="Capture le trafic du câble (ARP, DHCP, TDP 20002) : trouve un équipement dans n'importe quelle plage">Écoute passive</button>
  <input type="number" id="secs" value="180" min="10" max="600" style="width:62px" title="Durée d'écoute (s)"> s
  <button class="danger" id="btnStop" disabled>Stop</button>
  <div class="spacer"></div>
  <div class="seg" id="filter">
    <button data-f="all" class="on">Tous</button><button data-f="pharos">PharOS</button><button data-f="tplink">TP-Link</button><button data-f="unifi">UniFi</button><button data-f="netgear">NETGEAR</button><button data-f="qnap">QNAP</button><button data-f="tuya">Tuya</button><button data-f="amazon">Amazon</button>
  </div>
</div>

<main>
  <div class="list">
    <table>
      <thead><tr><th>Équipement</th><th>Adresse IP</th><th>MAC</th><th>Fabricant</th><th>Interface</th><th>Services</th><th>Vu</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
    <div class="empty" id="empty"><b>Aucun équipement pour l'instant</b>Choisis l'interface réseau, puis <em>Rechercher</em>. Pharos, TP-Link, Tuya/Smart Life et Amazon sont identifiés.<br>Un Pharos dans une plage inconnue : <em>Écoute passive</em>, il s'annonce en moins d'une minute.</div>
  </div>
  <aside id="detail"><div class="empty" style="padding:40px 0"><b>Sélectionne un équipement</b>pour l'ouvrir, t'y connecter ou changer son IP.</div></aside>
</main>

<footer>
  <div class="bar"><span>Journal</span><span id="jobs"></span><div class="spacer"></div><div class="aliases" id="aliases"></div></div>
  <div id="log"></div>
</footer>
<div id="toast"></div>
<div id="modal"><div class="box" id="modalBox"></div></div>

<script>
const TOKEN = new URLSearchParams(location.search).get('t');
let S = null, selected = null, filter = 'all', ifaceTouched = false, logLen = 0;
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

async function api(path, body){
  const r = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json','X-Token':TOKEN}, body:JSON.stringify(body||{})});
  const j = await r.json().catch(()=>({}));
  if(!r.ok){ toast(j.error || 'Erreur'); throw new Error(j.error); }
  refresh(); return j;
}
const KIND_LABEL = {pharos:'PharOS', tplink:'TP-Link', unifi:'UniFi', netgear:'NETGEAR', qnap:'QNAP', tuya:'Tuya / Smart Life', amazon:'Amazon', other:'Équipement'};
function displayName(d){
  if(d.kind === 'pharos') return d.model || 'PharOS';
  return d.name || d.model || d.title || (d.kind === 'other' ? 'Équipement' : KIND_LABEL[d.kind]);
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
  rp.textContent = S.root ? 'Droits admin' : 'Sans droits admin : adresses temporaires et écoute indisponibles';
  rp.className = 'pill' + (S.root ? '' : ' warn');

  // interfaces
  const sel = $('iface'), cur = sel.value;
  sel.innerHTML = S.interfaces.map(i => {
    const ips = i.ipv4.map(a => a.ip + '/' + a.prefix).join(', ') || 'sans IP';
    const lbl = i.label && i.label !== i.name ? `${esc(i.name)} — ${esc(i.label)}` : esc(i.name);
    return `<option value="${esc(i.name)}">${i.active ? '●' : '○'} ${lbl} — ${esc(ips)}</option>`;
  }).join('');
  if(cur && S.interfaces.some(i => i.name === cur)) sel.value = cur;
  else if(!ifaceTouched){
    const wired = S.interfaces.find(i => i.active && !i.wireless && i.ipv4.length) || S.interfaces.find(i => i.active && !i.wireless) || S.interfaces.find(i => i.active) || S.interfaces[0];
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
  const list = S.devices.filter(d => filter === 'all' || (filter === 'tplink' ? (d.kind === 'tplink' || d.kind === 'pharos') : d.kind === filter));
  $('empty').style.display = list.length ? 'none' : 'block';
  if(!list.length && S.devices.length){ $('empty').innerHTML = `<b>${S.devices.length} équipement(s) masqué(s) par le filtre</b>Clique sur <em>Tous</em> pour les voir.`; }
  $('rows').innerHTML = list.map(d => {
    const name = displayName(d);
    const svc = (d.ports||[]).map(p => `<span class="tag">${{22:'SSH',80:'HTTP',443:'HTTPS'}[p]||p}</span>`).join('')
      + (d.tdp ? '<span class="tag tdp">TDP</span>' : '')
      + (d.announced ? `<span class="tag tdp">${esc(d.announced)}</span>` : '')
      + (d.conflict ? '<span class="tag out" style="color:var(--err)">conflit IP</span>' : '')
      + (d.update_available ? '<span class="tag upd">MAJ dispo</span>' : '')
      + (d.tuya && d.tuya.parent ? `<span class="tag">via ${esc(d.tuya.parent)}</span>` : '')
      + (d.ip && !d.in_range ? '<span class="tag out">hors plage</span>' : '');
    return `<tr class="row ${d.id === selected ? 'sel' : ''}" data-id="${esc(d.id)}">
      <td><span class="dot ${d.kind}"></span>${esc(name)}</td>
      <td class="mono">${d.ip ? esc(d.ip) : d.ipv6 ? '<span class="hint">IPv6 seule</span>' : '—'}${d.ips.length > 1 ? ` <span class="hint">+${d.ips.length-1}</span>` : ''}</td>
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
  const kindLbl = KIND_LABEL[d.kind];
  const busy = Object.keys(S.jobs).length > 0;
  const hasWeb = (d.ports||[]).some(p => p === 80 || p === 443);
  const guessNet = d.ip ? d.ip.split('.').slice(0,3).join('.') + '.' : '';
  $('detail').innerHTML = `
    <h2>${esc(displayName(d))}</h2>
    <div class="sub">${esc((d.model && d.model !== displayName(d) && d.kind !== 'pharos' ? d.model : '') || (d.title !== displayName(d) ? d.title : '') || (d.kind === 'other' ? 'Identification partielle' : kindLbl))}</div>
    <dl>
      <dt>IP</dt><dd class="mono">${esc(d.ips.join(', ') || '—')}</dd>
      <dt>MAC</dt><dd class="mono">${esc(d.mac || '—')}</dd>
      ${d.ipv6 ? `<dt>IPv6</dt><dd class="mono">${esc(d.ipv6)}</dd>` : ''}
      <dt>Type</dt><dd>${esc(kindLbl)}${d.model && displayName(d) !== d.model ? ' · ' + esc(d.model) : ''}</dd>
      ${d.name ? `<dt>Nom</dt><dd>${esc(d.name)}</dd>` : ''}
      <dt>Fabricant</dt><dd>${esc(d.vendor || 'inconnu')}</dd>
      ${d.tuya ? `<dt>ID Tuya</dt><dd class="mono">${esc(d.tuya.gw_id || '—')}</dd><dt>Produit</dt><dd class="mono">${esc(d.tuya.product_key || '—')} · v${esc(d.tuya.version)}</dd>` : ''}
      ${(d.services||[]).length ? `<dt>Services</dt><dd>${esc(d.services.join(', '))}</dd>` : ''}
      <dt>Interface</dt><dd>${esc(d.iface || '—')}</dd>
      <dt>Joignable</dt><dd>${d.reachable === null ? '<span class="hint">non testé</span>' : d.reachable ? 'oui' : 'non'}${d.ip && !d.in_range ? ' · <span style="color:var(--warn)">hors de tes plages</span>' : ''}</dd>
      <dt>SSH</dt><dd class="mono">${esc(d.ssh || '—')}</dd>
      <dt>Serveur web</dt><dd>${esc(d.server || '—')}</dd>
      ${d.firmware ? `<dt>Firmware</dt><dd>${esc(d.firmware)}</dd>` : ''}
      ${(d.fw_modules||[]).map(m => `<dt>${esc(m.module)}</dt><dd>${esc(m.current||'?')}${m.latest && m.latest !== m.current ? ` → <b style="color:var(--ok)">${esc(m.latest)}</b>` : ' (à jour)'}</dd>`).join('')}
      ${d.tuya && d.tuya.gateway ? `<dt>Capteurs</dt><dd>${S.devices.filter(x => x.tuya && x.tuya.parent === d.name).map(x => esc(x.name + ' (' + x.model + ')')).join('<br>') || 'aucun'}</dd>` : ''}
      <dt>Source</dt><dd>${esc(d.sources.join(', '))}</dd>
    </dl>
    ${(d.actions||[]).filter(a => a.id !== 'web').length ? `<div class="actions">${d.actions.filter(a => a.id !== 'web').map(a => `<button data-vact="${esc(a.id)}" data-confirm="${esc(a.confirm||'')}" ${busy?'disabled':''}>${esc(a.label)}</button>`).join('')}</div>` : ''}
    <div class="actions">
      ${d.ip && !d.in_range ? `<button class="primary" data-act="reach" ${busy||!S.root?'disabled':''}>Rendre joignable (alias ${esc(guessNet)}x sur ${esc(d.iface || $('iface').value)})</button>` : ''}
      ${!d.ip && d.web_local ? `<button class="primary" data-act="weblocal">Ouvrir l'interface web (via IPv6)</button><p class="hint" style="margin:0">IPv4 inconnue : l'app relaie l'interface web par IPv6. Tu y liras son IP dans Network → LAN, sans reset.</p>` : ''}
      <button ${d.ip?'':'disabled'} data-act="web" class="${d.in_range && hasWeb ? 'primary' : ''}">Ouvrir l'interface web (https)</button>
      <button ${d.ip?'':'disabled'} data-act="webhttp">Ouvrir en http</button>
      <button ${d.ip||d.ipv6?'':'disabled'} data-act="ssh">Session SSH…</button>
      <button ${(d.ip||d.ipv6)&&!busy?'':'disabled'} data-act="refresh">Ré-identifier</button>
    </div>
    ${d.kind === 'pharos' || d.kind === 'tplink' ? `<div class="card">
      <h3>Changer l'adresse IP</h3>
      <ol>
        <li>Ouvre l'interface web et connecte-toi (usine : <span class="mono">admin / admin</span>).</li>
        <li><b>Network</b> → <b>LAN</b> : passe en <em>Static</em>, saisis la nouvelle IP, le masque et la passerelle, puis <b>Save</b>.</li>
        <li>Indique la nouvelle IP ci-dessous : l'outil ajoute l'alias nécessaire et attend que l'équipement revienne.</li>
      </ol>
      <div class="row2"><input type="text" id="newIp" placeholder="Nouvelle IP ex. 192.168.3.20" class="mono"><input type="number" id="newPfx" value="24" min="8" max="30" style="flex:none;width:58px" title="Préfixe"></div>
      <button data-act="watch" ${busy?'disabled':''}>Suivre la nouvelle IP</button>
      <p class="hint" style="margin:8px 0 0">Le reste de la configuration (mode, SSID, sécurité…) se fait dans l'interface web PharOS, comme avec Pharos Control.</p>
    </div>` : ''}
    ${d.kind === 'pharos' || d.kind === 'tplink' ? `<div class="card">
      <h3>Session SSH</h3>
      <div class="row2"><input type="text" id="sshUser" value="admin" class="mono"></div>
      <p class="hint" style="margin:0">Mêmes identifiants que l'interface web. Algorithmes anciens autorisés pour les vieux firmwares.</p>
    </div>` : ''}`;
}

document.addEventListener('click', async e => {
  const row = e.target.closest('tr.row');
  if(row){ selected = row.dataset.id; detailKey=''; render(); return; }
  const rm = e.target.closest('[data-rm]');
  if(rm){ const [iface, ip] = rm.dataset.rm.split('|'); return api('/api/alias/remove', {iface, ip}).catch(()=>{}); }
  const f = e.target.closest('#filter button');
  if(f){ filter = f.dataset.f; document.querySelectorAll('#filter button').forEach(b => b.classList.toggle('on', b === f)); render(); return; }
  const va = e.target.closest('[data-vact]');
  if(va){
    if(va.dataset.confirm && !confirm(va.dataset.confirm)) return;
    return api('/api/action', {id:selected, action:va.dataset.vact}).catch(()=>{});
  }
  const tab = e.target.closest('[data-acct]');
  if(tab){ showAccounts(tab.dataset.acct); return; }
  const a = e.target.closest('[data-act]');
  if(!a) return;
  const d = S.devices.find(x => x.id === selected); if(!d) return;
  const act = a.dataset.act;
  try{
    if(act === 'reach') await api('/api/reach', {id:d.id, iface:d.iface || $('iface').value, prefix:24});
    // Ouvert par le navigateur lui-même : jamais par le moteur administrateur.
    if(act === 'web') window.open(d.web && !d.web_local ? d.web : `https://${d.ip}/`, '_blank', 'noopener');
    if(act === 'webhttp') window.open(`http://${d.ip}/`, '_blank', 'noopener');
    if(act === 'weblocal') window.open(d.web_local, '_blank', 'noopener');
    if(act === 'ssh') await api('/api/ssh', {ip:d.ip || d.ipv6, user:($('sshUser')||{}).value || 'admin'});
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
$('btnListen').onclick = () => api('/api/listen', {iface:$('iface').value, seconds:+$('secs').value || 180}).catch(()=>{});
$('btnStop').onclick = () => api('/api/stop').catch(()=>{});
let HELP = null, acctTab = 'tuya';
function md(t){  // mini Markdown pour l'aide : titres, gras, code, listes
  return esc(t).split('\n\n').map(b => {
    b = b.replace(/\*\*(.+?)\*\*/g,'<b>$1</b>').replace(/\*(.+?)\*/g,'<i>$1</i>').replace(/`(.+?)`/g,'<code>$1</code>');
    if(b.startsWith('## ')) return '<h2>' + b.slice(3) + '</h2>';
    const lines = b.split('\n');
    if(lines.every(l => /^(- |\d\. )/.test(l))) return '<ul>' + lines.map(l => '<li>' + l.replace(/^(- |\d\. )/,'') + '</li>').join('') + '</ul>';
    return '<p>' + lines.map(l => l.replace(/^- /,'• ')).join('<br>') + '</p>';
  }).join('');
}
async function showAccounts(tab){
  acctTab = tab || acctTab;
  if(!HELP){ try{ HELP = await (await fetch('/api/help', {headers:{'X-Token':TOKEN}})).json(); }catch(_){ HELP = {}; } }
  const st = (S && S.integrations && S.integrations[acctTab]) || {};
  const form = acctTab === 'tuya' ? `
    <label>Access ID / Client ID</label><input type="text" id="aId" autocomplete="off">
    <label>Access Secret / Client Secret</label><input type="password" id="aSecret" autocomplete="off">
    <label>Région du projet (Data Center)</label><select id="aRegion"><option value="eu">Europe centrale</option><option value="weu">Europe de l'Ouest</option><option value="us">États-Unis (Ouest)</option><option value="eus">États-Unis (Est)</option><option value="cn">Chine</option><option value="in">Inde</option></select>` : `
    <label>Adresse du contrôleur</label><input type="text" id="aUrl" placeholder="https://10.10.10.1">
    <label>Identifiant (administrateur local)</label><input type="text" id="aUser" autocomplete="off">
    <label>Mot de passe</label><input type="password" id="aPw" autocomplete="off">
    <label>Site</label><input type="text" id="aSite" value="default">`;
  $('modalBox').innerHTML = `
    <div class="tabs"><button data-acct="tuya" class="${acctTab==='tuya'?'on':''}">Tuya / Smart Life</button><button data-acct="unifi" class="${acctTab==='unifi'?'on':''}">UniFi</button><div class="spacer"></div><button id="mClose">Fermer</button></div>
    <p>État : <b>${esc(st.status || 'non configuré')}</b>${st.last_sync ? ' · dernière synchro ' + esc(st.last_sync) : ''}</p>
    ${form}
    <label class="chk" style="margin-top:10px"><input type="checkbox" id="aPersist"> Mémoriser sur cet ordinateur (fichier protégé)</label>
    <div class="row2" style="margin-top:12px"><button class="primary" id="mSave">Enregistrer et synchroniser</button>
      ${st.configured ? '<button id="mSync">Synchroniser</button><button class="danger" id="mForget">Oublier</button>' : ''}</div>
    <div class="help">${md((HELP && HELP[acctTab]) || '')}</div>`;
  $('modal').style.display = 'flex';
  $('mClose').onclick = () => $('modal').style.display = 'none';
  $('mSave').onclick = async () => {
    const body = acctTab === 'tuya'
      ? {vendor:'tuya', access_id:$('aId').value, access_secret:$('aSecret').value, region:$('aRegion').value}
      : {vendor:'unifi', url:$('aUrl').value, username:$('aUser').value, password:$('aPw').value, site:$('aSite').value};
    body.persist = $('aPersist').checked;
    try{ await api('/api/account', body); $('modal').style.display = 'none'; }catch(_){}
  };
  if($('mSync')) $('mSync').onclick = () => api('/api/sync', {vendor:acctTab}).then(() => $('modal').style.display = 'none').catch(()=>{});
  if($('mForget')) $('mForget').onclick = () => api('/api/account/forget', {vendor:acctTab}).then(() => showAccounts()).catch(()=>{});
}
$('btnAccounts').onclick = () => showAccounts();
$('btnQuit').onclick = async () => {
  if(!confirm('Arrêter Pharos Finder ? Les adresses temporaires seront retirées.')) return;
  try{ await fetch('/api/quit', {method:'POST', headers:{'Content-Type':'application/json','X-Token':TOKEN}, body:'{}'}); }catch(_){}
  clearInterval(POLL);
  document.body.innerHTML = '<div class="empty" style="margin:auto"><b>Pharos Finder est arrêté</b>Tu peux fermer cet onglet.</div>';
};

refresh(); const POLL = setInterval(refresh, 1000);
</script>
</body>
</html>"""

if __name__ == "__main__":
    main()
