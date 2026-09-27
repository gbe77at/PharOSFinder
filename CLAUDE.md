# Pharos Finder — brief pour Claude Code

## Mission

Finaliser et livrer **Pharos Finder**, une app macOS native (SwiftUI) pour découvrir les équipements **TP-Link PharOS** (CPE510 et CPE710 en priorité ; CPE210/220/520/605/610, WBS…) sur le réseau local, les rendre joignables et ouvrir leur configuration. L'app s'inspire de Pharos Control (TP-Link) et de QNAP Finder.

**Livrable attendu :** `build/PharosFinder.dmg`, contenant une app universelle (arm64 + x86_64) signée ad hoc, qui se lance et trouve un Pharos.

Le code est déjà écrit dans ce dossier, mais **le Swift n'a jamais été compilé** : il a été rédigé sans compilateur macOS. Ton travail : compiler, corriger, tester, livrer.

## Contexte utilisateur

- Guillaume, Mac Apple Silicon (M5), macOS récent, Xcode / Command Line Tools installés, Python via miniconda (`~/miniconda3/bin/python3`).
- Le Mac est relié en Ethernet à un petit LAN via un adaptateur USB (`en11`, « USB 10/100/1000 LAN »), par exemple en `192.168.3.204/24`.
- Le Pharos cible peut être dans **n'importe quelle plage IP**, y compris inconnue, et il peut ne pas y avoir de DHCP (le Mac tombe alors en `169.254.x.x`).
- Il communique en français. L'interface et les messages de l'app sont en français, en tutoiement.

## Étapes

1. `chmod +x build.sh && ./build.sh` et lire les erreurs de compilation.
2. Corriger les erreurs Swift **sans changer l'architecture** (voir plus bas). Recompiler jusqu'au succès en arm64 et x86_64.
3. Tester le moteur seul (voir « Tests »).
4. Lancer l'app (`open "build/Pharos Finder.app"`) et vérifier les scénarios d'acceptation.
5. `./build.sh --open` pour produire et ouvrir le DMG final.
6. Donner un résumé court : ce qui a été corrigé, ce qui a été testé, et le chemin du DMG.

## Architecture (à conserver)

```
PharosFinder/
├── build.sh                     # swiftc ×2 archs → lipo → Info.plist → iconutil → codesign ad hoc → hdiutil UDZO
├── Sources/
│   ├── PharosFinderApp.swift    # @main, Window scene, menu « Réseau », AppDelegate (start/shutdown)
│   ├── Engine.swift             # lance et pilote le moteur Python (ObservableObject)
│   ├── Models.swift             # Codable miroir du JSON /api/state
│   ├── ContentView.swift        # toolbar + Table + inspecteur + journal + barre d'état
│   ├── DetailView.swift         # inspecteur d'un équipement
│   └── Components.swift         # badges, états vides, journal, barre d'état, options
└── Resources/
    ├── pharos_finder.py         # moteur de découverte (Python ≥ 3.8, stdlib uniquement)
    └── AppIcon.iconset/         # PNG 16→1024, convertis en .icns par iconutil
```

**Principe :** l'UI SwiftUI (qui tourne comme l'utilisateur) pilote un moteur Python embarqué, lancé **en root** via `NSAppleScript` `do shell script … with administrator privileges`. Cela affiche la boîte de mot de passe native de macOS. Le moteur est root parce que les alias IP (`ifconfig alias`) et `tcpdump` l'exigent. Si l'utilisateur refuse le mot de passe, le moteur est lancé sans privilèges (mode dégradé : balayage OK, pas d'alias ni d'écoute).

**Communication :** HTTP local `127.0.0.1:<port libre>`, en-tête `X-Token: <jeton aléatoire>`. L'app interroge l'état chaque seconde.

**Cycle de vie :**
- L'app passe `--parent-pid <pid de l'app>`. Le moteur s'arrête et retire ses alias si l'app disparaît, même en cas de crash.
- À la fermeture normale, l'app envoie `POST /api/quit`.

Contraintes :
- Pas de dépendance Python externe, pas de package Swift externe, pas de projet Xcode : `swiftc` + `build.sh` suffisent.
- Cible macOS 13+ (`Window`, `Grid`, `Table`, `.formStyle(.grouped)`). Compilation en `-swift-version 5 -parse-as-library`.
- `Engine` n'est **pas** `@MainActor` : les mises à jour publiées passent par `MainActor.run` / `DispatchQueue.main`. Garder cette approche pour éviter les erreurs d'isolation.
- La session `URLSession` vers le moteur ignore les proxys (`connectionProxyDictionary`). Les sondes HTTP du moteur utilisent `ProxyHandler({})`. **Ne pas retirer** : un proxy d'entreprise détournerait sinon les requêtes vers le Pharos.
- Les actions « ouvrir le web » (`NSWorkspace`) et « SSH » (`NSAppleScript` → Terminal) sont faites par l'app, jamais par le moteur root.

## API du moteur (`pharos_finder.py`)

Lancement : `python3 pharos_finder.py --port P --token T --no-browser --parent-pid PID`. Sans `--token`, il génère un jeton et sert aussi une UI web de secours sur `/?t=<jeton>`.

| Méthode | Route | Corps JSON | Effet |
|---|---|---|---|
| GET | `/api/state` | — | instantané complet (voir schéma) |
| POST | `/api/scan` | `iface, factory, full, extra` | balayage de la plage de l'interface, plus les plages d'usine via alias |
| POST | `/api/listen` | `iface, seconds` | écoute passive `tcpdump` (ARP, DHCP, UDP 20002) |
| POST | `/api/stop` | — | arrête les tâches en cours |
| POST | `/api/reach` | `id, iface, prefix` | ajoute un alias dans le /24 de l'équipement |
| POST | `/api/refresh` | `id` | ré-identifie (ports 22/80/443, bannière SSH, page web) |
| POST | `/api/watch` | `ip, prefix, iface` | suit une nouvelle IP après changement (max 240 s) |
| POST | `/api/alias/remove` | `iface, ip` | retire un alias |
| POST | `/api/clear` | — | vide la liste |
| POST | `/api/quit` | — | retire les alias et quitte |

Erreur → HTTP 400 `{"error": "message en français"}`. Une seule tâche par nom à la fois (`scan`, `listen`, `reach`, `refresh`, `watch`).

Schéma `/api/state` (clés snake_case, décodées en camelCase côté Swift avec `.convertFromSnakeCase`) :

```json
{
  "version": "1.0", "root": true, "mac_os": true,
  "interfaces": [{"name":"en11","mac":"6c:1f:…","ipv4":[{"ip":"192.168.3.204","mask":"255.255.255.0","prefix":24}],
                  "status":"active","label":"USB 10/100/1000 LAN","active":true,"aliases":["192.168.0.250"]}],
  "devices": [{"id":"50:c7:bf:…","mac":"50:c7:bf:…","ip":"192.168.0.254","ips":["192.168.0.254"],"vendor":"TP-Link",
               "kind":"pharos|tplink|other","iface":"en11","model":"CPE510","title":"…","server":"…","ports":[22,443],
               "ssh":"SSH-2.0-dropbear_…","sources":["balayage","écoute"],"tdp":false,"pharos_hint":true,
               "tplink_hint":true,"web":"https://…","reachable":true,"last_seen":"17:05:12","fingerprinted":true,
               "in_range":true}],
  "log": [{"t":"17:05:12","level":"info|ok|warn|error","msg":"…"}],
  "jobs": {"scan": {"label":"Recherche","elapsed":4}},
  "aliases": [{"iface":"en11","ip":"192.168.0.250","mask":"255.255.255.0","keep_reason":"accès à 192.168.0.0/24"}]
}
```

## Connaissances métier PharOS

- IP d'usine : **192.168.0.254/24**. Identifiants web d'usine : `admin` / `admin`. Interface web en HTTPS (vieux firmwares : HTTP), certificat auto-signé.
- Pharos Control découvre les équipements via **UDP 20002** (protocole TDP propriétaire et **non documenté**) et les gère en **SSH port 22** (Dropbear, parfois avec d'anciens algorithmes). Ne pas inventer de format TDP : on écoute ce trafic, on ne l'émule pas.
- Changer l'IP : interface web → *Network* → *LAN* → *Static*. L'API web PharOS n'est pas documentée : on ne la pilote pas, on guide l'utilisateur puis on suit la nouvelle IP.
- Identification : préfixe OUI TP-Link (liste embarquée, sinon `api.macvendors.com`), titre ou contenu de la page (« PharOS », modèles `CPE\d{3}` / `WBS\d{3}`), bannière SSH.

## Détails macOS utiles

- `arp -an` affiche des MAC sans zéros de tête (`50:c7:bf:1:2:3`) : c'est normalisé dans `norm_mac`.
- Le masque d'`ifconfig` est en hexa (`0xffffff00`). `ping -W` est en **millisecondes** sur macOS.
- Alias : `ifconfig en11 alias 192.168.0.250 255.255.255.0` / `ifconfig en11 -alias 192.168.0.250`.
- Sous `do shell script` root, le PATH est `/usr/bin:/bin:/usr/sbin:/sbin` : `ifconfig`, `arp`, `ping`, `tcpdump` et `networksetup` y sont.
- Info.plist déclare `NSLocalNetworkUsageDescription`, `NSAppleEventsUsageDescription` (Terminal) et `NSAllowsLocalNetworking`.
- Recherche de Python par l'app : Homebrew, python.org, `~/miniconda3`, `~/miniforge3`, `~/anaconda3`, puis `/usr/bin/python3`. Version ≥ 3.8 vérifiée.

## Tests

**Moteur seul, sans droits :**
```bash
python3 Resources/pharos_finder.py --port 8811 --token T --no-browser &
curl -s -H "X-Token: T" http://127.0.0.1:8811/api/state | python3 -m json.tool | head -40
curl -s -X POST -H "X-Token: T" -H 'Content-Type: application/json' -d '{"iface":"en11","factory":false}' http://127.0.0.1:8811/api/scan
sleep 15; curl -s -H "X-Token: T" http://127.0.0.1:8811/api/state | python3 -c "import json,sys;[print(l['msg']) for l in json.load(sys.stdin)['log']]"
curl -s -X POST -H "X-Token: T" -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:8811/api/quit
```
Vérifier que `interfaces` contient `en11` avec son label, et qu'aucun alias ne reste ensuite (`ifconfig en11`).

**Scénarios d'acceptation dans l'app :**
1. Au lancement, la fenêtre s'affiche puis la boîte de mot de passe apparaît. La barre d'état passe ensuite à « Moteur actif · droits admin ».
2. L'interface filaire active est présélectionnée dans la barre d'outils.
3. **Rechercher** : le journal défile, les équipements apparaissent dans le tableau, et un Pharos est sélectionné automatiquement avec son modèle.
4. Un équipement « hors plage » affiche la carte orange. **Rendre joignable** ajoute un alias visible en bas à droite, et l'équipement devient « Joignable ».
5. **Ouvrir l'interface web** ouvre `https://<ip>/` dans le navigateur par défaut. **SSH** ouvre Terminal.
6. **Écoute passive** (60 s) avec redémarrage du Pharos : il apparaît même s'il est dans une plage inconnue.
7. Quitter (⌘Q) : `ifconfig` ne montre plus aucun alias ajouté. Tuer l'app (`kill -9`) : le moteur disparaît en 2 à 3 s et retire aussi ses alias.
8. Refuser le mot de passe : l'app reste utilisable en mode dégradé, avec un message clair dans la barre d'état.
9. Mode clair et mode sombre lisibles. Fenêtre utilisable à la taille minimale (1020×640).

## Points de vigilance à la compilation

- `infoRow(...) -> some View` renvoie un `GridRow`. Si l'alignement du `Grid` casse, remplacer par des `GridRow` écrits directement dans `infoGrid`.
- `onChange(of:)` à un paramètre est déprécié en macOS 14 : un avertissement est acceptable, sinon passer à la variante à deux paramètres avec une garde de disponibilité.
- `freePort()` utilise les sockets BSD (`bind` / `getsockname`). En cas de conflit de nom, qualifier avec `Darwin.bind`.
- `NSAppleScript.executeAndReturnError` renvoie une valeur non utilisée : un avertissement est acceptable.
- Si le SDK impose des isolations `@MainActor` (Xcode récent), annoter les méthodes concernées plutôt que de rendre `Engine` entièrement `@MainActor`.

## Windows et Linux (PC)

Le même moteur `pharos_finder.py` tourne sur Windows et Linux ; il sert alors son UI web
(`/?t=<jeton>`) dans le navigateur. Couche plateforme dans le moteur :

| | macOS | Windows | Linux (dont DGX Spark ARM64) |
|---|---|---|---|
| Interfaces | `ifconfig` + `networksetup` | PowerShell `Get-NetAdapter`/`Get-NetIPAddress` (JSON, cache 4 s) | `ip -j addr` |
| ARP | `arp -an` | `arp -a` (index d'interface en hexa → nom) | `ip -4 neigh` |
| Alias | `ifconfig alias` | `netsh … add address store=active` (+ coexistence DHCP/statique si besoin, remise à l'état initial) | `ip addr add` |
| Écoute | `tcpdump` | socket brute `SIO_RCVALL` (IPv4 seulement : DHCP → MAC, TDP, IP) | `tcpdump`, sinon `AF_PACKET` |
| Droits | `do shell script … with administrator privileges` | relance UAC (`ShellExecuteW runas`), refus → mode limité | `sudo` |

- Windows : `ping` renvoie 0 même si l'hôte est injoignable → on teste « TTL= ». `os.kill(pid, 0)`
  enverrait un Ctrl+C → `pid_alive` passe par `OpenProcess`. Fermeture de la console : `SetConsoleCtrlHandler`.
- Le navigateur n'est jamais lancé en admin (`explorer.exe <url>` ; l'UI web ouvre les pages elle-même).
- `.github/workflows/build.yml` : tests + smoke test (`tests/smoke.py`) sur macOS, Windows, Linux x64 et
  ARM64 ; `PharosFinder.exe` (PyInstaller, onefile, console) ; DMG ; release sur tag `v*`.

## Hors périmètre

Notarisation Apple, émulation du protocole TDP, pilotage de l'API web PharOS, mise à jour firmware.
