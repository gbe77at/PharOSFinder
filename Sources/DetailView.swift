import SwiftUI

struct DetailView: View {
    @EnvironmentObject private var engine: Engine
    let device: Device
    @State private var newIP = ""
    @State private var prefix = 24
    @State private var sshUser = "admin"
    @State private var pendingAction: DeviceAction?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                if device.conflict == true { conflictCard }
                if device.isOutOfRange { outOfRangeCard }
                actions
                if let acts = device.actions?.filter({ $0.id != "web" }), !acts.isEmpty {
                    GroupBox {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(acts) { a in
                                Button(a.label) {
                                    if a.confirm != nil { pendingAction = a } else { engine.action(device, a.id) }
                                }
                                .disabled(engine.isBusy)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                    } label: {
                        Label("Gestion", systemImage: "slider.horizontal.below.rectangle")
                    }
                }
                GroupBox {
                    infoGrid.padding(8)
                } label: {
                    Label("Informations", systemImage: "info.circle")
                }
                if device.isManageable {
                    GroupBox {
                        ipChange.padding(8)
                    } label: {
                        Label("Changer l'adresse IP", systemImage: "arrow.triangle.2.circlepath")
                    }
                }
            }
            .padding(20)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .confirmationDialog(pendingAction?.confirm ?? "", isPresented: Binding(
            get: { pendingAction != nil }, set: { if !$0 { pendingAction = nil } }), titleVisibility: .visible) {
            Button(pendingAction?.label ?? "Confirmer") {
                if let a = pendingAction { engine.action(device, a.id) }
                pendingAction = nil
            }
            Button("Annuler", role: .cancel) { pendingAction = nil }
        }
    }

    // MARK: En-tête

    private var icon: String {
        switch device.kind {
        case "pharos", "tplink": return "antenna.radiowaves.left.and.right"
        case "tuya": return "lightbulb.fill"
        case "amazon": return device.model == "Fire TV" ? "tv" : "hifispeaker.fill"
        case "unifi": return "wifi.router"
        case "netgear": return "rectangle.connected.to.line.below"
        case "qnap": return "externaldrive.connected.to.line.below"
        case "printer3d": return "cube.fill"
        default: return "network"
        }
    }

    private var header: some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 13, style: .continuous)
                    .fill(Device.color(for: device.kind).gradient)
                Image(systemName: icon)
                    .font(.system(size: 24, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .frame(width: 56, height: 56)
            .shadow(color: .black.opacity(0.12), radius: 3, y: 1)

            VStack(alignment: .leading, spacing: 3) {
                Text(device.displayName).font(.title2.weight(.bold)).lineLimit(1)
                Text(device.subtitle).foregroundStyle(.secondary).lineLimit(2)
                HStack(spacing: 6) {
                    Badge(text: device.kindLabel, color: Device.color(for: device.kind))
                    if let r = device.reachable {
                        Badge(text: r ? "Joignable" : "Ne répond pas", color: r ? .green : .red)
                    }
                }
            }
        }
    }

    // MARK: Conflit d'adresse

    private var conflictCard: some View {
        Label("Un autre équipement utilise aussi \(device.ip ?? "cette IP"). Débranche l'un des deux ou change son adresse, sinon les connexions iront au hasard vers l'un ou l'autre.",
              systemImage: "exclamationmark.2")
            .font(.callout)
            .foregroundStyle(.red)
            .fixedSize(horizontal: false, vertical: true)
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.red.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }

    // MARK: Hors plage

    private var outOfRangeCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Hors de tes plages IP", systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundStyle(.orange)
            Text("Ton Mac ne peut pas joindre \(device.ip ?? "") en l'état. Pharos Finder peut ajouter une adresse temporaire dans son réseau sur \(device.iface ?? engine.selectedIface). Elle sera retirée à la fermeture.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button { engine.reach(device) } label: {
                Label("Rendre joignable", systemImage: "link")
            }
            .buttonStyle(.borderedProminent)
            .tint(.orange)
            .disabled(!engine.isAdmin || engine.isBusy)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }

    // MARK: Actions

    private var actions: some View {
        VStack(spacing: 8) {
            Button { engine.openWeb(device, https: true) } label: {
                Label(device.ip == nil && device.webLocal != nil ? "Ouvrir l'interface web (via IPv6)" : "Ouvrir l'interface web",
                      systemImage: "safari")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(!device.canOpenWeb)
            if device.ip == nil && device.ipv6 != nil {
                Text("IPv4 inconnue : Pharos Finder relaie l'interface web par IPv6. Tu y liras son adresse IP dans Network → LAN, sans reset.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack(spacing: 8) {
                Button { engine.openWeb(device, https: false) } label: {
                    Text("En http").frame(maxWidth: .infinity)
                }
                .help("Ouvre http:// (anciens firmwares)")
                .disabled(device.ip == nil)
                Button { engine.openSSH(device, user: sshUser) } label: {
                    Label("SSH", systemImage: "terminal").frame(maxWidth: .infinity)
                }
                .help("Ouvre une session SSH dans Terminal")
                Button { engine.refresh(device) } label: {
                    Label("Ré-identifier", systemImage: "arrow.clockwise").frame(maxWidth: .infinity)
                }
                .disabled(engine.isBusy)
            }
            .controlSize(.large)
            .disabled(device.sshAddress == nil)

            HStack {
                Text("Utilisateur SSH").foregroundStyle(.secondary)
                TextField("admin", text: $sshUser)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
                    .frame(maxWidth: 140)
                Spacer()
            }
            .font(.callout)
        }
    }

    // MARK: Informations

    private var infoGrid: some View {
        Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 8) {
            infoRow("IP", device.ips.isEmpty ? "—" : device.ips.joined(separator: ", "), mono: true)
            if let n = device.name {
                infoRow("Nom", n)
            }
            if let r = device.role {
                infoRow("Rôle", r)
            }
            if let p = device.printer3d, !p.summary.isEmpty {
                infoRow("Imprimante", p.summary)
            }
            infoRow("MAC", device.mac ?? "—", mono: true)
            if let v6 = device.ipv6 {
                infoRow("IPv6", v6, mono: true)
            }
            infoRow("Fabricant", device.vendor ?? "inconnu")
            infoRow("Interface", device.iface ?? "—")
            infoRow("Ports ouverts", device.ports.isEmpty ? "aucun détecté" : device.ports.map { String($0) }.joined(separator: ", "))
            infoRow("SSH", device.ssh ?? "—", mono: true)
            infoRow("Serveur web", device.server ?? "—")
            if let fw = device.firmware {
                infoRow("Firmware", fw)
            }
            ForEach(device.fwModules ?? [], id: \.self) { m in
                infoRow(m.module, m.hasUpdate ? "\(m.current ?? "?") → \(m.latest ?? "?") (mise à jour disponible)"
                                              : "\(m.current ?? "?") (à jour)")
            }
            if device.tuya?.gateway == true {
                let subs = (engine.snapshot?.devices ?? []).filter { $0.tuya?.parent == device.name }
                infoRow("Capteurs", subs.isEmpty ? "aucun" : subs.map { "\($0.displayName) (\($0.model ?? "?"))" }.joined(separator: "\n"))
            }
            if let t = device.tuya {
                infoRow("ID Tuya", t.gwId ?? "—", mono: true)
                infoRow("Produit Tuya", "\(t.productKey ?? "—") · v\(t.version ?? "?")", mono: true)
            }
            if let sv = device.services, !sv.isEmpty {
                infoRow("Services", sv.joined(separator: ", "))
            }
            infoRow("Trouvé par", device.sources.joined(separator: ", "))
            if device.tdp {
                infoRow("TDP", "trafic de découverte Pharos (UDP 20002) observé")
            }
        }
    }

    private func infoRow(_ key: String, _ value: String, mono: Bool = false) -> some View {
        GridRow {
            Text(key)
                .foregroundStyle(.secondary)
                .gridColumnAlignment(.trailing)
            Text(value)
                .font(mono ? .system(.body, design: .monospaced) : .body)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: Changement d'IP

    private var ipChange: some View {
        VStack(alignment: .leading, spacing: 10) {
            StepRow(number: 1, text: "Ouvre l'interface web et connecte-toi (usine : admin / admin).")
            StepRow(number: 2, text: "Network → LAN : passe en Static, saisis la nouvelle IP, le masque et la passerelle, puis Save.")
            StepRow(number: 3, text: "Indique la nouvelle IP ici : Pharos Finder ajoute l'adresse temporaire nécessaire et attend que l'équipement réponde.")
            HStack(spacing: 6) {
                TextField("ex. 192.168.3.20", text: $newIP)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
                Text("/").foregroundStyle(.secondary)
                TextField("24", value: $prefix, format: .number)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 44)
            }
            Button { engine.watch(ip: newIP, prefix: prefix, device: device) } label: {
                Label("Suivre la nouvelle IP", systemImage: "scope")
            }
            .disabled(!isValidIPv4(newIP) || !(8...30).contains(prefix) || engine.isBusy)
        }
    }
}

struct StepRow: View {
    let number: Int
    let text: String
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text("\(number)")
                .font(.caption.weight(.bold))
                .foregroundStyle(.white)
                .frame(width: 18, height: 18)
                .background(Circle().fill(Color.accentColor))
            Text(text)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
