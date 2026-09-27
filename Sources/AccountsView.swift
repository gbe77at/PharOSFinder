import Security
import SwiftUI

/// Identifiants des comptes (Tuya, UniFi), rangés dans le trousseau macOS.
enum AccountStore {
    private static let service = "fr.guillaume.pharosfinder.comptes"

    static func load(_ vendor: String) -> [String: String]? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: service,
                                kSecAttrAccount as String: vendor,
                                kSecReturnData as String: true,
                                kSecMatchLimit as String: kSecMatchLimitOne]
        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess, let data = item as? Data else { return nil }
        return try? JSONDecoder().decode([String: String].self, from: data)
    }

    static func save(_ vendor: String, _ fields: [String: String]) {
        guard let data = try? JSONEncoder().encode(fields) else { return }
        delete(vendor)
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: service,
                                kSecAttrAccount as String: vendor,
                                kSecAttrLabel as String: "Pharos Finder – compte \(vendor)",
                                kSecValueData as String: data]
        SecItemAdd(q as CFDictionary, nil)
    }

    static func delete(_ vendor: String) {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: service,
                                kSecAttrAccount as String: vendor]
        SecItemDelete(q as CFDictionary)
    }
}

struct AccountsView: View {
    @EnvironmentObject private var engine: Engine
    @Environment(\.dismiss) private var dismiss
    @State private var vendor = "tuya"
    @State private var fields: [String: String] = [:]

    private let regions = [("eu", "Europe centrale"), ("weu", "Europe de l'Ouest"), ("us", "États-Unis (Ouest)"),
                           ("eus", "États-Unis (Est)"), ("cn", "Chine"), ("in", "Inde")]

    private var integration: Integration? { engine.snapshot?.integrations?[vendor] }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Picker("", selection: $vendor) {
                    Text("Tuya / Smart Life").tag("tuya")
                    Text("UniFi").tag("unifi")
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 280)
                Spacer()
                Button("Fermer") { dismiss() }.keyboardShortcut(.cancelAction)
            }
            .padding(16)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    status
                    form
                    buttons
                    Divider()
                    HelpText(markdown: engine.help[vendor] ?? "Chargement de l'aide…")
                }
                .padding(18)
            }
        }
        .frame(width: 640, height: 640)
        .onAppear { engine.loadHelp(); reload() }
        .onChange(of: vendor) { _ in reload() }
    }

    private func reload() { fields = AccountStore.load(vendor) ?? (vendor == "unifi" ? ["site": "default"] : ["region": "eu"]) }

    private func binding(_ key: String) -> Binding<String> {
        Binding(get: { fields[key] ?? "" }, set: { fields[key] = $0 })
    }

    private var status: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(integration?.ok == true ? Color.green : integration?.configured == true ? Color.orange : Color.secondary)
                .frame(width: 8, height: 8)
            Text(integration?.status ?? "non configuré").font(.callout.weight(.semibold))
            if let t = integration?.lastSync { Text("· dernière synchro \(t)").font(.callout).foregroundStyle(.secondary) }
        }
    }

    @ViewBuilder
    private var form: some View {
        Form {
            if vendor == "tuya" {
                TextField("Access ID / Client ID", text: binding("access_id"))
                SecureField("Access Secret / Client Secret", text: binding("access_secret"))
                Picker("Région du projet", selection: binding("region")) {
                    ForEach(regions, id: \.0) { Text($0.1).tag($0.0) }
                }
            } else {
                TextField("Adresse du contrôleur", text: binding("url"), prompt: Text("https://10.10.10.1"))
                TextField("Identifiant (administrateur local)", text: binding("username"))
                SecureField("Mot de passe", text: binding("password"))
                TextField("Site", text: binding("site"))
            }
        }
        .formStyle(.grouped)
        .frame(height: vendor == "tuya" ? 150 : 190)
    }

    private var buttons: some View {
        HStack {
            Button("Enregistrer et synchroniser") {
                AccountStore.save(vendor, fields)
                engine.configureAccount(vendor, fields)
            }
            .buttonStyle(.borderedProminent)
            .disabled(vendor == "tuya" ? (fields["access_id"] ?? "").isEmpty || (fields["access_secret"] ?? "").isEmpty
                                       : (fields["url"] ?? "").isEmpty || (fields["username"] ?? "").isEmpty)
            if integration?.configured == true {
                Button("Synchroniser") { engine.post("sync", ["vendor": vendor]) }
                Button("Oublier", role: .destructive) {
                    AccountStore.delete(vendor)
                    engine.post("account/forget", ["vendor": vendor])
                    reload()
                }
            }
            Spacer()
            Text("Rangé dans le trousseau macOS").font(.caption).foregroundStyle(.secondary)
        }
    }
}

/// Affiche l'aide (Markdown simple : titres ##, gras, italique, code, listes).
struct HelpText: View {
    let markdown: String

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            ForEach(Array(markdown.components(separatedBy: "\n\n").enumerated()), id: \.offset) { _, block in
                if block.hasPrefix("## ") {
                    Text(block.dropFirst(3)).font(.title3.weight(.bold))
                } else {
                    Text(inline(block.split(separator: "\n").map { $0.hasPrefix("- ") ? "•  " + $0.dropFirst(2) : String($0) }
                                .joined(separator: "\n")))
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
            }
        }
        .font(.callout)
    }

    private func inline(_ s: String) -> AttributedString {
        (try? AttributedString(markdown: s, options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)))
            ?? AttributedString(s)
    }
}
