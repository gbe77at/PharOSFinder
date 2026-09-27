import AppKit
import Foundation

enum EngineStatus: Equatable {
    case starting
    case running(admin: Bool)
    case failed(String)
}

/// Pilote le moteur de découverte (pharos_finder.py embarqué dans l'app) :
/// lancement avec les droits administrateur, interrogation de l'état, envoi des actions.
final class Engine: ObservableObject {
    static let shared = Engine()

    // État publié (toujours modifié sur le thread principal)
    @Published var snapshot: Snapshot?
    @Published var status: EngineStatus = .starting
    @Published var errorMessage: String?
    @Published var selectedIface: String = ""

    // Options de recherche
    @Published var factory = true
    @Published var fullSweep = false
    @Published var extraRanges = ""
    @Published var listenSeconds = 180

    let logURL = FileManager.default.temporaryDirectory.appendingPathComponent("PharosFinder-moteur.log")

    private var port = 0
    private var autoSelectedIface = ""
    private let token = UUID().uuidString.replacingOccurrences(of: "-", with: "")
    private var pollTask: Task<Void, Never>?
    private var userProcess: Process?
    private let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.connectionProxyDictionary = ["HTTPEnable": false, "HTTPSEnable": false]
        c.timeoutIntervalForRequest = 8
        return URLSession(configuration: c)
    }()

    // MARK: - États dérivés

    var isRunning: Bool { if case .running = status { return true } else { return false } }
    var isAdmin: Bool { if case .running(let a) = status { return a } else { return false } }
    var isBusy: Bool { !(snapshot?.jobs.isEmpty ?? true) }
    func jobRunning(_ key: String) -> Bool { snapshot?.jobs[key] != nil }
    var interfaces: [NetIface] { snapshot?.interfaces ?? [] }
    var currentIface: NetIface? { interfaces.first { $0.name == selectedIface } }

    // MARK: - Cycle de vie

    func start() {
        guard pollTask == nil else { return }
        status = .starting
        guard let script = Bundle.main.path(forResource: "pharos_finder", ofType: "py") else {
            status = .failed("Moteur introuvable dans l'application.")
            return
        }
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            guard let python = Engine.findPython() else {
                DispatchQueue.main.async {
                    self.status = .failed("Python 3 introuvable. Installe les Command Line Tools (xcode-select --install) ou Python depuis python.org, puis clique sur Réessayer.")
                }
                return
            }
            let port = Engine.freePort()
            let pid = ProcessInfo.processInfo.processIdentifier
            let args = [python, script, "--port", String(port), "--token", self.token,
                        "--no-browser", "--parent-pid", String(pid)]
            try? FileManager.default.removeItem(at: self.logURL)
            DispatchQueue.main.async {
                self.port = port
                if !self.launchAsAdmin(args) { self.launchAsUser(args) }
                self.pollTask = Task.detached { [weak self] in await self?.pollLoop() }
            }
        }
    }

    func restart() {
        shutdown()
        pollTask = nil
        snapshot = nil
        start()
    }

    /// Arrêt propre : le moteur retire ses alias IP avant de quitter.
    func shutdown() {
        pollTask?.cancel()
        if port != 0, let url = URL(string: "http://127.0.0.1:\(port)/api/quit") {
            var req = URLRequest(url: url)
            req.httpMethod = "POST"
            req.setValue(token, forHTTPHeaderField: "X-Token")
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = Data("{}".utf8)
            req.timeoutInterval = 1.5
            let sem = DispatchSemaphore(value: 0)
            session.dataTask(with: req) { _, _, _ in sem.signal() }.resume()
            _ = sem.wait(timeout: .now() + 2)
        }
        userProcess?.terminate()
        userProcess = nil
    }

    /// Sur le thread principal (NSAppleScript n'est pas sûr ailleurs). La boîte de mot de passe
    /// native, au nom de l'app, est modale : bloquer la boucle pendant la saisie est voulu.
    private func launchAsAdmin(_ args: [String]) -> Bool {
        let cmd = args.map(Engine.shellQuote).joined(separator: " ")
            + " > " + Engine.shellQuote(logURL.path) + " 2>&1 &"
        let escaped = cmd.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let source = "do shell script \"\(escaped)\" with prompt \"Pharos Finder a besoin des droits administrateur pour poser des adresses IP temporaires et écouter le réseau.\" with administrator privileges"
        var err: NSDictionary?
        let script = NSAppleScript(source: source)
        _ = script?.executeAndReturnError(&err)
        return err == nil && script != nil
    }

    private func launchAsUser(_ args: [String]) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: args[0])
        p.arguments = Array(args.dropFirst())
        FileManager.default.createFile(atPath: logURL.path, contents: nil)
        if let h = try? FileHandle(forWritingTo: logURL) {
            p.standardOutput = h
            p.standardError = h
        }
        do {
            try p.run()
            userProcess = p
        } catch {
            status = .failed("Lancement du moteur impossible : \(error.localizedDescription)")
        }
    }

    private func pollLoop() async {
        var failures = 0
        while !Task.isCancelled {
            let snap = await fetchState()
            failures = snap == nil ? failures + 1 : 0
            let f = failures
            await MainActor.run { self.apply(snap, failures: f) }
            try? await Task.sleep(nanoseconds: 1_000_000_000)
        }
    }

    private func apply(_ snap: Snapshot?, failures: Int) {
        if let s = snap {
            snapshot = s
            if status != .running(admin: s.root) { status = .running(admin: s.root) }
            // Choix automatique tant que l'utilisateur n'a rien choisi : un câble branché après le
            // lancement (Ethernet) passe devant le Wi-Fi.
            let best = Engine.pickDefault(s.interfaces)
            if selectedIface.isEmpty || !s.interfaces.contains(where: { $0.name == selectedIface })
                || (selectedIface == autoSelectedIface && best != selectedIface) {
                selectedIface = best
                autoSelectedIface = best
            }
            return
        }
        switch status {
        case .starting where failures >= 20:
            status = .failed("Le moteur ne démarre pas. Consulte le journal du moteur (menu Réseau).")
        case .running where failures >= 4:
            status = .failed("Le moteur s'est arrêté. Clique sur Réessayer.")
        default:
            break
        }
    }

    private func fetchState() async -> Snapshot? {
        guard port != 0, let url = URL(string: "http://127.0.0.1:\(port)/api/state") else { return nil }
        var req = URLRequest(url: url)
        req.setValue(token, forHTTPHeaderField: "X-Token")
        guard let result = try? await session.data(for: req),
              (result.1 as? HTTPURLResponse)?.statusCode == 200 else { return nil }
        let dec = JSONDecoder()
        dec.keyDecodingStrategy = .convertFromSnakeCase
        do {
            return try dec.decode(Snapshot.self, from: result.0)
        } catch {
            NSLog("PharosFinder: décodage impossible : \(error)")
            return nil
        }
    }

    // MARK: - Actions

    func post(_ path: String, _ body: [String: Any] = [:]) {
        guard port != 0, let url = URL(string: "http://127.0.0.1:\(port)/api/\(path)") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue(token, forHTTPHeaderField: "X-Token")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        let request = req
        Task.detached { [weak self] in
            guard let self = self else { return }
            do {
                let (data, resp) = try await self.session.data(for: request)
                if (resp as? HTTPURLResponse)?.statusCode != 200 {
                    let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
                    let msg = obj?["error"] as? String ?? "Le moteur a refusé l'action."
                    await MainActor.run { self.errorMessage = msg }
                }
                let snap = await self.fetchState()
                await MainActor.run { if let s = snap { self.snapshot = s } }
            } catch {
                await MainActor.run { self.errorMessage = "Moteur injoignable : \(error.localizedDescription)" }
            }
        }
    }

    func scan() {
        guard !selectedIface.isEmpty else { return }
        post("scan", ["iface": selectedIface, "factory": factory, "full": fullSweep, "extra": extraRanges])
    }

    func listen() {
        guard !selectedIface.isEmpty else { return }
        post("listen", ["iface": selectedIface, "seconds": listenSeconds])
    }

    func stop() { post("stop") }
    func clear() { post("clear") }
    func refresh(_ d: Device) { post("refresh", ["id": d.id]) }
    func reach(_ d: Device) { post("reach", ["id": d.id, "iface": d.iface ?? selectedIface, "prefix": 24]) }
    func removeAlias(_ a: IPAlias) { post("alias/remove", ["iface": a.iface, "ip": a.ip]) }

    func watch(ip: String, prefix: Int, device: Device) {
        post("watch", ["ip": ip.trimmingCharacters(in: .whitespaces), "prefix": prefix,
                       "iface": device.iface ?? selectedIface])
    }

    func openWeb(_ d: Device, https: Bool) {
        // IPv4 inconnue : le moteur relaie l'interface web via IPv6 sur 127.0.0.1.
        let target = d.ip.map { "\(https ? "https" : "http")://\($0)/" } ?? d.webLocal
        guard let t = target, let url = URL(string: t) else { return }
        NSWorkspace.shared.open(url)
    }

    func openSSH(_ d: Device, user: String) {
        guard let ip = d.sshAddress,
              ip.range(of: "^([0-9.]+|fe80:[0-9A-Fa-f:]+%[A-Za-z0-9]+)$", options: .regularExpression) != nil
        else { return }
        let u = user.trimmingCharacters(in: .whitespaces)
        guard !u.isEmpty, u.range(of: "^[A-Za-z0-9._-]{1,32}$", options: .regularExpression) != nil else {
            errorMessage = "Nom d'utilisateur SSH invalide."
            return
        }
        let ssh = "ssh -o StrictHostKeyChecking=accept-new -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa \(u)@\(ip)"
        let source = "tell application \"Terminal\"\nactivate\ndo script \"\(ssh)\"\nend tell"
        var err: NSDictionary?
        NSAppleScript(source: source)?.executeAndReturnError(&err)
        if let e = err {
            errorMessage = "Impossible d'ouvrir Terminal : \(e[NSAppleScript.errorMessage] as? String ?? "autorisation refusée")"
        }
    }

    func openEngineLog() { NSWorkspace.shared.open(logURL) }

    // MARK: - Utilitaires

    static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    static func findPython() -> String? {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let candidates = [
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3",
            "/Library/Frameworks/Python.framework/Versions/Current/bin/python3",
            "\(home)/miniconda3/bin/python3",
            "\(home)/miniforge3/bin/python3",
            "\(home)/anaconda3/bin/python3",
            "/usr/bin/python3",
        ]
        for c in candidates where FileManager.default.isExecutableFile(atPath: c) {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: c)
            p.arguments = ["-c", "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"]
            p.standardOutput = FileHandle.nullDevice
            p.standardError = FileHandle.nullDevice
            do {
                try p.run()
                p.waitUntilExit()
                if p.terminationStatus == 0 { return c }
            } catch {
                continue
            }
        }
        return nil
    }

    static func freePort() -> Int {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return Int.random(in: 49200...60000) }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let ok: Bool = withUnsafeMutablePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                bind(fd, sa, len) == 0 && getsockname(fd, sa, &len) == 0
            }
        }
        return ok ? Int(UInt16(bigEndian: addr.sin_port)) : Int.random(in: 49200...60000)
    }

    static func pickDefault(_ ifaces: [NetIface]) -> String {
        if let wired = ifaces.first(where: { $0.active && !$0.isWireless && !$0.ipv4.isEmpty }) {
            return wired.name
        }
        return (ifaces.first(where: { $0.active }) ?? ifaces.first)?.name ?? ""
    }
}
