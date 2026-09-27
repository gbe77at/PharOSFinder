import AppKit
import SwiftUI

@main
struct PharosFinderApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var engine = Engine.shared

    var body: some Scene {
        Window("Pharos Finder", id: "main") {
            ContentView()
                .environmentObject(engine)
                .frame(minWidth: 1020, minHeight: 640)
        }
        .defaultSize(width: 1260, height: 800)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Réseau") {
                Button("Rechercher") { engine.scan() }
                    .keyboardShortcut("r")
                    .disabled(!engine.isRunning)
                Button("Écoute passive") { engine.listen() }
                    .keyboardShortcut("l")
                    .disabled(!engine.isAdmin)
                Button("Arrêter") { engine.stop() }
                    .keyboardShortcut(".")
                    .disabled(!engine.isBusy)
                Divider()
                Button("Vider la liste") { engine.clear() }
                Button("Redémarrer le moteur") { engine.restart() }
                Button("Ouvrir le journal du moteur") { engine.openEngineLog() }
            }
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Laisse la fenêtre apparaître avant la demande de mot de passe administrateur.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) {
            Engine.shared.start()
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationWillTerminate(_ notification: Notification) {
        Engine.shared.shutdown()
    }
}
