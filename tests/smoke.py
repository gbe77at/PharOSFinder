"""Test de fumée du moteur réel (sans droits admin) : python3 tests/smoke.py [chemin_moteur]

Lance le moteur, vérifie /api/state, balaye la plage de la première interface active,
puis demande l'arrêt. Utilisé par la CI sur macOS, Windows et Linux.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT, TOKEN = 8811, "smoke"


def call(path, body=None):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", headers={"X-Token": TOKEN})
    if body is not None:
        req.data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=30) as r:
        return json.load(r)


def main():
    engine = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "Resources", "pharos_finder.py")
    cmd = [engine] if engine.lower().endswith(".exe") else [sys.executable, engine]
    cmd += ["--port", str(PORT), "--token", TOKEN, "--no-browser", "--no-elevate"]
    proc = subprocess.Popen(cmd)
    try:
        state = None
        for _ in range(60):
            try:
                state = call("/api/state")
                break
            except OSError:
                time.sleep(0.5)
        assert state, "le moteur ne répond pas"
        print("plateforme:", state["platform"], "admin:", state["root"])
        for i in state["interfaces"]:
            print(f"  {i['name']!r} {i['label']!r} actif={i['active']} wifi={i.get('wireless')} {i['ipv4']}")
        active = [i for i in state["interfaces"] if i["active"] and i["ipv4"]]
        assert active, "aucune interface active avec IPv4 détectée"
        call("/api/scan", {"iface": active[0]["name"], "factory": False})
        for _ in range(240):
            time.sleep(1)
            state = call("/api/state")
            if not state["jobs"]:
                break
        for line in state["log"]:
            print(f"  [{line['level']}] {line['msg']}")
        assert not state["jobs"], "la recherche ne se termine pas"
        assert any("Recherche terminée" in l["msg"] for l in state["log"]), "recherche en échec"
        assert not any(l["level"] == "error" for l in state["log"]), "erreur dans le journal"
        print("équipements:", len(state["devices"]))
        call("/api/quit", {})
        proc.wait(timeout=10)
        print("OK")
    finally:
        if proc.poll() is None:
            proc.kill()


if __name__ == "__main__":
    main()
