import SwiftUI

@main
struct XsteerApp: App {
    @StateObject private var tunnel = TunnelManager()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(tunnel)
                .task { await tunnel.load() }
                // Настройка, которой поделились из «Файлов», почты или мессенджера.
                .onOpenURL { url in
                    Task { await importConf(from: url) }
                }
        }
    }

    private func importConf(from url: URL) async {
        // Файл, пришедший «поделиться», лежит во временной папке и может быть защищён: без
        // startAccessing чтение вернёт отказ на файле, который человек только что выбрал.
        let needsAccess = url.startAccessingSecurityScopedResource()
        defer { if needsAccess { url.stopAccessingSecurityScopedResource() } }
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return }
        await tunnel.save(conf: text)
    }
}
