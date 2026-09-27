import Foundation

// Miroir du JSON renvoyé par le moteur (GET /api/state). Clés snake_case → camelCase.

struct Snapshot: Decodable {
    var version: String
    var root: Bool
    var interfaces: [NetIface]
    var devices: [Device]
    var log: [LogEntry]
    var jobs: [String: Job]
    var aliases: [IPAlias]
}

struct IPv4Addr: Decodable, Hashable {
    var ip: String
    var mask: String
    var prefix: Int
}

struct NetIface: Decodable, Identifiable, Hashable {
    var name: String
    var mac: String?
    var ipv4: [IPv4Addr]
    var status: String?
    var label: String
    var active: Bool
    var aliases: [String]
    var wireless: Bool?

    var id: String { name }
    var isWireless: Bool { wireless ?? label.lowercased().contains("wi-fi") }
    var summary: String { ipv4.map { "\($0.ip)/\($0.prefix)" }.joined(separator: ", ") }
    var menuTitle: String {
        let dot = active ? "●" : "○"
        let base = label == name ? name : "\(label) (\(name))"
        return summary.isEmpty ? "\(dot)  \(base)" : "\(dot)  \(base) — \(summary)"
    }
}

struct Device: Decodable, Identifiable, Hashable {
    var id: String
    var mac: String?
    var ip: String?
    var ips: [String]
    var vendor: String?
    var kind: String
    var iface: String?
    var model: String?
    var title: String?
    var server: String?
    var ports: [Int]
    var ssh: String?
    var sources: [String]
    var tdp: Bool
    var reachable: Bool?
    var lastSeen: String?
    var inRange: Bool
    var ipv6: String?
    var webLocal: String?
    var firmware: String?
    var announced: String?
    var conflict: Bool?
    var name: String?
    var services: [String]?
    var tuya: TuyaInfo?

    /// Adresse pour SSH : IPv4, sinon IPv6 link-local (fe80::…%en11).
    var sshAddress: String? { ip ?? ipv6 }
    var canOpenWeb: Bool { ip != nil || webLocal != nil }

    var displayName: String {
        if kind == "pharos" { return model ?? "PharOS" }
        if let n = name, !n.isEmpty { return n }
        if let m = model { return m }
        if let t = title, !t.isEmpty { return t }
        return kind == "other" ? "Équipement" : kindLabel
    }

    var kindLabel: String {
        switch kind {
        case "pharos": return "PharOS"
        case "tplink": return "TP-Link"
        case "tuya": return "Tuya / Smart Life"
        case "amazon": return "Amazon"
        default: return "Autre"
        }
    }

    var subtitle: String {
        if let m = model, m != displayName, kind != "pharos" { return m }
        if let t = title, !t.isEmpty, t != displayName { return t }
        switch kind {
        case "pharos": return "Interface PharOS détectée"
        case "tplink": return "Équipement TP-Link"
        case "tuya": return "Appareil Tuya / Smart Life"
        case "amazon": return "Appareil Amazon"
        default: return "Identification partielle"
        }
    }

    var isManageable: Bool { kind == "pharos" || kind == "tplink" }

    var isOutOfRange: Bool { ip != nil && !inRange }
}

struct TuyaInfo: Decodable, Hashable {
    var gwId: String?
    var productKey: String?
    var version: String?
}

struct LogEntry: Decodable, Hashable {
    var t: String
    var level: String
    var msg: String
}

struct Job: Decodable, Hashable {
    var label: String
    var elapsed: Int
}

struct IPAlias: Decodable, Hashable {
    var iface: String
    var ip: String
    var mask: String
    var keepReason: String?
}

func isValidIPv4(_ s: String) -> Bool {
    let parts = s.trimmingCharacters(in: .whitespaces).split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return false }
    return parts.allSatisfy { p in
        guard !p.isEmpty, p.count <= 3, let v = Int(p) else { return false }
        return (0...255).contains(v)
    }
}
