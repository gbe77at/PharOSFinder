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
    host = f"[{ip}]" if ":" in ip else ip
    if 443 in open_ports:
        tries.append(f"https://{host}/")
    if 80 in open_ports:
        tries.append(f"http://{host}/")
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
            "fingerprinted": False, "ipv6": None, "web_local": None}


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
        if not d or not (d["ip"] or d.get("ipv6")):
            return
        ip4, mac = d["ip"], d["mac"]
        ip = ip4 or d["ipv6"]  # IPv6 link-local quand l'IPv4 est inconnue
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
    if not ip4 and web:
        info["web_local"] = ensure_tunnel(dev_id, ip, 443 if 443 in open_ports else 80)
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


def _listen_tcpdump(iface, stop):
    cmd = ["tcpdump", "-i", iface["name"], "-n", "-e", "-l"]
    if iface["mac"]:
        cmd += ["not", "ether", "src", iface["mac"]]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    with LOCK:
        JOBS["listen"]["proc"] = proc

    def _watchdog():  # readline() bloque tant qu'aucune trame n'arrive
        while proc.poll() is None and not stop():
            time.sleep(0.3)
        if proc.poll() is None:
            proc.terminate()

    threading.Thread(target=_watchdog, daemon=True).start()
    try:
        for line in proc.stdout:
            if stop():
                break
            yield parse_tcpdump_line(line, iface["mac"])
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
            c["in_range"] = bool(d["ip"]) and not d["ip"].startswith("169.254.") and \
                any(ipaddress.IPv4Address(d["ip"]) in n for _, n in nets)
            devs.append(c)
        order = {"pharos": 0, "tplink": 1, "other": 2}
        devs.sort(key=lambda x: (order[x["kind"]], tuple(int(p) for p in (x["ip"] or "255.255.255.255").split("."))))
        return {
            "version": VERSION, "root": IS_ROOT, "mac_os": IS_MAC, "platform": PLATFORM,
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
                    os._exit(0)
        threading.Thread(target=_watch_parent, args=(args.parent_pid,), daemon=True).start()

    if not IS_ROOT:
        print("⚠️  Lancé sans droits administrateur : balayage OK, mais pas d'adresse temporaire "
              "ni d'écoute passive.")

    atexit.register(cleanup_aliases)

    def _sig(*_):
        cleanup_aliases()
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
      ${d.ipv6 ? `<dt>IPv6</dt><dd class="mono">${esc(d.ipv6)}</dd>` : ''}
      <dt>Fabricant</dt><dd>${esc(d.vendor || 'inconnu')}</dd>
      <dt>Interface</dt><dd>${esc(d.iface || '—')}</dd>
      <dt>Joignable</dt><dd>${d.reachable === null ? '<span class="hint">non testé</span>' : d.reachable ? 'oui' : 'non'}${d.ip && !d.in_range ? ' · <span style="color:var(--warn)">hors de tes plages</span>' : ''}</dd>
      <dt>SSH</dt><dd class="mono">${esc(d.ssh || '—')}</dd>
      <dt>Serveur web</dt><dd>${esc(d.server || '—')}</dd>
      <dt>Source</dt><dd>${esc(d.sources.join(', '))}</dd>
    </dl>
    <div class="actions">
      ${d.ip && !d.in_range ? `<button class="primary" data-act="reach" ${busy||!S.root?'disabled':''}>Rendre joignable (alias ${esc(guessNet)}x sur ${esc(d.iface || $('iface').value)})</button>` : ''}
      ${!d.ip && d.web_local ? `<button class="primary" data-act="weblocal">Ouvrir l'interface web (via IPv6)</button><p class="hint" style="margin:0">IPv4 inconnue : l'app relaie l'interface web par IPv6. Tu y liras son IP dans Network → LAN, sans reset.</p>` : ''}
      <button ${d.ip?'':'disabled'} data-act="web" class="${d.in_range && hasWeb ? 'primary' : ''}">Ouvrir l'interface web (https)</button>
      <button ${d.ip?'':'disabled'} data-act="webhttp">Ouvrir en http</button>
      <button ${d.ip||d.ipv6?'':'disabled'} data-act="ssh">Session SSH…</button>
      <button ${(d.ip||d.ipv6)&&!busy?'':'disabled'} data-act="refresh">Ré-identifier</button>
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
    // Ouvert par le navigateur lui-même : jamais par le moteur administrateur.
    if(act === 'web') window.open(`https://${d.ip}/`, '_blank', 'noopener');
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
