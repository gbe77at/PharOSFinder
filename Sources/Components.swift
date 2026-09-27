import SwiftUI

extension Device {
    static func color(for kind: String) -> Color {
        switch kind {
        case "pharos": return .blue
        case "tplink": return .teal
        case "tuya": return .orange
        case "amazon": return .indigo
        default: return .gray
        }
    }
}

struct KindDot: View {
    let kind: String
    var body: some View {
        Circle().fill(Device.color(for: kind)).frame(width: 9, height: 9)
    }
}

struct Badge: View {
    let text: String
    let color: Color
    var body: some View {
        Text(text)
            .font(.system(size: 10.5, weight: .semibold))
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .foregroundStyle(color)
            .background(color.opacity(0.13), in: Capsule())
    }
}

struct ServiceBadges: View {
    let device: Device
    var body: some View {
        HStack(spacing: 4) {
            ForEach(device.ports, id: \.self) { p in
                Badge(text: p == 22 ? "SSH" : p == 80 ? "HTTP" : p == 443 ? "HTTPS" : "\(p)", color: .secondary)
            }
            if device.tdp { Badge(text: "TDP", color: .teal) }
            if let a = device.announced { Badge(text: a, color: .blue) }
            if let v = device.tuya?.version { Badge(text: "Tuya v\(v)", color: .orange) }
            if device.conflict == true { Badge(text: "conflit IP", color: .red) }
            if device.isOutOfRange { Badge(text: "hors plage", color: .orange) }
            if device.ports.isEmpty && !device.tdp && !device.isOutOfRange && device.announced == nil && device.tuya == nil {
                Text("—").foregroundStyle(.tertiary)
            }
        }
    }
}

// MARK: - États vides

struct EmptyStateView: View {
    @EnvironmentObject private var engine: Engine
    let hidden: Int
    @Binding var filter: DeviceFilter

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "antenna.radiowaves.left.and.right")
                .font(.system(size: 52, weight: .light))
                .foregroundStyle(.tint)
            if engine.jobRunning("scan") || engine.jobRunning("listen") {
                Text(engine.jobRunning("listen") ? "Écoute du câble en cours…" : "Recherche en cours…")
                    .font(.title3.weight(.semibold))
                ProgressView().controlSize(.small)
                if engine.jobRunning("listen") {
                    Text("Débranche puis rebranche l'alimentation PoE du Pharos pour qu'il s'annonce.")
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 420)
                }
            } else if hidden > 0 {
                Text("\(hidden) équipement(s) masqué(s) par le filtre")
                    .font(.title3.weight(.semibold))
                Button("Afficher tous les équipements") { filter = .all }
            } else {
                Text("Aucun équipement pour l'instant")
                    .font(.title3.weight(.semibold))
                Text("Choisis l'interface réseau dans la barre d'outils, puis lance une recherche : Pharos, TP-Link, Tuya/Smart Life et Amazon sont identifiés.\nUn Pharos dans une plage IP inconnue s'annonce tout seul en moins d'une minute.")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 460)
                HStack(spacing: 10) {
                    Button { engine.scan() } label: {
                        Label("Rechercher", systemImage: "magnifyingglass").padding(.horizontal, 6)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!engine.isRunning || engine.selectedIface.isEmpty)
                    Button { engine.listen() } label: {
                        Label("Écoute passive", systemImage: "ear").padding(.horizontal, 6)
                    }
                    .disabled(!engine.isAdmin || engine.selectedIface.isEmpty)
                }
                .controlSize(.large)
                .padding(.top, 4)
            }
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .controlBackgroundColor))
    }
}

struct NoSelectionView: View {
    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: "cursorarrow.click.2")
                .font(.system(size: 34, weight: .light))
                .foregroundStyle(.secondary)
            Text("Sélectionne un équipement").font(.headline)
            Text("pour ouvrir son interface, t'y connecter en SSH ou changer son IP.")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(30)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

struct EngineBanner: View {
    @EnvironmentObject private var engine: Engine
    let message: String
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.octagon.fill").foregroundStyle(.red)
            Text(message).fixedSize(horizontal: false, vertical: true)
            Spacer()
            Button("Journal") { engine.openEngineLog() }
            Button("Réessayer") { engine.restart() }.buttonStyle(.borderedProminent)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
        .background(Color.red.opacity(0.08))
    }
}

// MARK: - Journal et barre d'état

struct LogPanel: View {
    @EnvironmentObject private var engine: Engine

    var body: some View {
        let lines = engine.snapshot?.log ?? []
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(lines.enumerated()), id: \.offset) { index, line in
                        HStack(alignment: .firstTextBaseline, spacing: 10) {
                            Text(line.t).foregroundStyle(.tertiary)
                            Text(line.msg)
                                .foregroundStyle(color(for: line.level))
                                .textSelection(.enabled)
                        }
                        .font(.system(size: 11.5, design: .monospaced))
                        .id(index)
                    }
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .onChange(of: lines.count) { count in
                if count > 0 { proxy.scrollTo(count - 1, anchor: .bottom) }
            }
            .onAppear {
                if !lines.isEmpty { proxy.scrollTo(lines.count - 1, anchor: .bottom) }
            }
        }
        .background(Color(nsColor: .textBackgroundColor))
    }

    private func color(for level: String) -> Color {
        switch level {
        case "ok": return .green
        case "warn": return .orange
        case "error": return .red
        default: return .primary
        }
    }
}

struct StatusBar: View {
    @EnvironmentObject private var engine: Engine
    @Binding var showLog: Bool

    var body: some View {
        let jobs = (engine.snapshot?.jobs ?? [:]).sorted { $0.key < $1.key }.map { $0.value }
        HStack(spacing: 12) {
            statusLabel
            ForEach(jobs, id: \.label) { job in
                HStack(spacing: 5) {
                    ProgressView().controlSize(.mini)
                    Text("\(job.label) · \(job.elapsed) s")
                }
                .foregroundStyle(Color.accentColor)
            }
            Spacer()
            ForEach(engine.snapshot?.aliases ?? [], id: \.self) { a in
                HStack(spacing: 3) {
                    Image(systemName: "pin.fill").font(.system(size: 9))
                    Text("\(a.ip) · \(a.iface)").font(.system(size: 11, design: .monospaced))
                    Button { engine.removeAlias(a) } label: {
                        Image(systemName: "xmark.circle.fill")
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                    .help("Retirer cette adresse temporaire")
                }
                .padding(.horizontal, 7)
                .padding(.vertical, 2)
                .background(Color.secondary.opacity(0.12), in: Capsule())
                .help(a.keepReason ?? "Adresse IP temporaire")
            }
            Button { showLog.toggle() } label: {
                Image(systemName: "list.bullet.rectangle")
            }
            .buttonStyle(.plain)
            .foregroundStyle(showLog ? Color.accentColor : Color.secondary)
            .help(showLog ? "Masquer le journal" : "Afficher le journal")
        }
        .font(.caption)
        .padding(.horizontal, 12)
        .frame(height: 30)
        .background(.bar)
    }

    @ViewBuilder
    private var statusLabel: some View {
        switch engine.status {
        case .starting:
            HStack(spacing: 6) {
                ProgressView().controlSize(.mini)
                Text("Démarrage du moteur…")
            }
        case .running(let admin):
            HStack(spacing: 6) {
                Circle().fill(admin ? Color.green : Color.orange).frame(width: 7, height: 7)
                Text(admin ? "Moteur actif · droits admin" : "Moteur actif · sans droits admin (écoute et adresses temporaires indisponibles)")
            }
        case .failed:
            HStack(spacing: 6) {
                Circle().fill(Color.red).frame(width: 7, height: 7)
                Text("Moteur arrêté")
            }
        }
    }
}

// MARK: - Options

struct OptionsView: View {
    @EnvironmentObject private var engine: Engine

    var body: some View {
        Form {
            Section("Recherche") {
                Toggle("Sonder les plages d'usine (192.168.0.x, 192.168.1.x)", isOn: $engine.factory)
                Toggle("Balayer entièrement ces plages", isOn: $engine.fullSweep)
                TextField("Autres plages", text: $engine.extraRanges, prompt: Text("10.0.0.0/24, 172.16.5.0/24"))
            }
            Section("Écoute passive") {
                Stepper("Durée : \(engine.listenSeconds) s", value: $engine.listenSeconds, in: 10...600, step: 10)
            }
            Section {
                Button("Vider la liste des équipements", role: .destructive) { engine.clear() }
            }
        }
        .formStyle(.grouped)
    }
}
