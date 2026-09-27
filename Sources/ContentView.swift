import SwiftUI

enum DeviceFilter: String, CaseIterable, Identifiable {
    case all = "Tous"
    case pharos = "PharOS"
    case tplink = "TP-Link"
    case unifi = "UniFi"
    case netgear = "NETGEAR"
    case qnap = "QNAP"
    case tuya = "Tuya"
    case amazon = "Amazon"
    var id: String { rawValue }
}

struct ContentView: View {
    @EnvironmentObject private var engine: Engine
    @State private var selection: Device.ID?
    @State private var filter: DeviceFilter = .all
    @State private var search = ""
    @State private var showOptions = false
    @State private var showLog = true
    @State private var showAccounts = false

    private var allDevices: [Device] { engine.snapshot?.devices ?? [] }

    private var devices: [Device] {
        allDevices
            .filter { d in
                switch filter {
                case .pharos: return d.kind == "pharos"
                case .tplink: return d.kind == "tplink" || d.kind == "pharos"
                case .tuya: return d.kind == "tuya"
                case .amazon: return d.kind == "amazon"
                case .unifi: return d.kind == "unifi"
                case .netgear: return d.kind == "netgear"
                case .qnap: return d.kind == "qnap"
                case .all: return true
                }
            }
            .filter { d in
                search.isEmpty
                    || [d.displayName, d.ip ?? "", d.mac ?? "", d.vendor ?? "", d.model ?? "", d.ips.joined(separator: " ")]
                        .joined(separator: " ").localizedCaseInsensitiveContains(search)
            }
    }

    private var selectedDevice: Device? { allDevices.first { $0.id == selection } }

    var body: some View {
        VStack(spacing: 0) {
            if case .failed(let message) = engine.status {
                EngineBanner(message: message)
                Divider()
            }
            HSplitView {
                deviceArea
                    .frame(minWidth: 580, maxWidth: .infinity, maxHeight: .infinity)
                Group {
                    if let d = selectedDevice {
                        DetailView(device: d).id(d.id)
                    } else {
                        NoSelectionView()
                    }
                }
                .frame(minWidth: 320, idealWidth: 360, maxWidth: 480, maxHeight: .infinity)
            }
            if showLog {
                Divider()
                LogPanel().frame(height: 150)
            }
            Divider()
            StatusBar(showLog: $showLog)
        }
        .toolbar { toolbarContent }
        .searchable(text: $search, placement: .toolbar, prompt: "IP, MAC, modèle…")
        .onChange(of: allDevices.map(\.id)) { ids in
            // Sélectionne automatiquement le premier PharOS trouvé.
            if selection == nil || !ids.contains(selection ?? "") {
                selection = allDevices.first(where: { $0.kind == "pharos" })?.id
            }
        }
        .sheet(isPresented: $showAccounts) {
            AccountsView().environmentObject(engine)
        }
        .alert("Pharos Finder",
               isPresented: Binding(get: { engine.errorMessage != nil },
                                    set: { if !$0 { engine.errorMessage = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(engine.errorMessage ?? "")
        }
    }

    // MARK: Barre d'outils

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .navigation) {
            Picker("Interface", selection: $engine.selectedIface) {
                if engine.interfaces.isEmpty {
                    Text("Recherche des interfaces…").tag("")
                }
                ForEach(engine.interfaces) { i in
                    Text(i.menuTitle).tag(i.name)
                }
            }
            .frame(width: 320)
            .help("Interface réseau reliée au Pharos (● = câble actif)")
        }
        ToolbarItemGroup(placement: .primaryAction) {
            Button { engine.scan() } label: {
                Label("Rechercher", systemImage: "magnifyingglass")
            }
            .help("Balaye la plage de l'interface et les plages d'usine PharOS (⌘R)")
            .disabled(!engine.isRunning || engine.jobRunning("scan") || engine.selectedIface.isEmpty)

            Button { engine.listen() } label: {
                Label("Écoute passive", systemImage: "ear")
            }
            .help("Écoute le câble pour trouver un équipement dans n'importe quelle plage IP. Redémarre le Pharos pendant l'écoute (⌘L)")
            .disabled(!engine.isAdmin || engine.jobRunning("listen") || engine.selectedIface.isEmpty)

            Button { engine.stop() } label: {
                Label("Arrêter", systemImage: "stop.fill")
            }
            .help("Arrête la recherche ou l'écoute en cours")
            .disabled(!engine.isBusy)

            Button { showAccounts = true } label: {
                Label("Comptes", systemImage: "person.badge.key")
            }
            .help("Relier Tuya / Smart Life et le contrôleur UniFi")

            Button { showOptions.toggle() } label: {
                Label("Options", systemImage: "slider.horizontal.3")
            }
            .help("Options de recherche")
            .popover(isPresented: $showOptions, arrowEdge: .bottom) {
                OptionsView().environmentObject(engine).frame(width: 360)
            }

            Picker("Filtre", selection: $filter) {
                ForEach(DeviceFilter.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.menu)
            .frame(width: 150)
            .help("Filtrer la liste")
        }
    }

    // MARK: Liste

    @ViewBuilder
    private var deviceArea: some View {
        if devices.isEmpty {
            EmptyStateView(hidden: allDevices.count, filter: $filter)
        } else {
            Table(devices, selection: $selection) {
                TableColumn("Équipement") { d in
                    HStack(spacing: 8) {
                        KindDot(kind: d.kind)
                        Text(d.displayName)
                            .fontWeight(d.kind == "pharos" ? .semibold : .regular)
                            .lineLimit(1)
                    }
                }
                .width(min: 140, ideal: 180)

                TableColumn("Adresse IP") { d in
                    HStack(spacing: 4) {
                        if let ip = d.ip {
                            Text(ip).font(.system(.body, design: .monospaced))
                        } else {
                            Text(d.ipv6 != nil ? "IPv6 seule" : "—").foregroundStyle(.secondary)
                        }
                        if d.ips.count > 1 {
                            Text("+\(d.ips.count - 1)").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                .width(min: 110, ideal: 130)

                TableColumn("MAC") { d in
                    Text(d.mac ?? "—").font(.system(.body, design: .monospaced)).foregroundStyle(.secondary)
                }
                .width(min: 130, ideal: 150)

                TableColumn("Type") { d in
                    Text(d.kind == "other" ? (d.vendor ?? "—") : d.kindLabel).lineLimit(1)
                }
                .width(min: 80, ideal: 110)

                TableColumn("Services") { d in
                    ServiceBadges(device: d)
                }
                .width(min: 120, ideal: 190)

                TableColumn("Vu à") { d in
                    Text(d.lastSeen ?? "").foregroundStyle(.secondary)
                }
                .width(min: 55, ideal: 65)
            }
        }
    }
}
