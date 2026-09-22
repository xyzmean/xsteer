import NetworkExtension
import SwiftUI
import UniformTypeIdentifiers
import Xsteer

struct ContentView: View {
    @EnvironmentObject private var tunnel: TunnelManager
    @State private var conf = ""
    @State private var showImporter = false
    @State private var newKey: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    HStack {
                        Circle()
                            .fill(color)
                            .frame(width: 10, height: 10)
                        Text(title)
                            .font(.headline)
                        Spacer()
                        if tunnel.status == .connecting || tunnel.status == .reasserting {
                            ProgressView()
                        }
                    }
                    Button(isOn ? "Отключить" : "Подключить") {
                        Task {
                            if isOn { tunnel.stop() } else { await tunnel.start() }
                        }
                    }
                    .disabled(conf.isEmpty)
                }

                if let st = tunnel.state, st.up {
                    Section("Соединение") {
                        row("Хаб", st.hub)
                        row("Ключ хаба", st.hubKey)
                        row("Соединений", "\(st.conns)")
                        row("MTU", st.mtuConfirmed > 0 ? "\(st.mtuConfirmed)" : "\(st.mtu)")
                        if st.handshakeAge >= 0 {
                            row("Рукопожатие", "\(st.handshakeAge) с назад")
                        }
                    }
                    Section("Счётчики") {
                        row("Отправлено", bytes(st.txBytes) + " · \(st.txPackets) пак.")
                        row("Получено", bytes(st.rxBytes) + " · \(st.rxPackets) пак.")
                        if st.dropped > 0 { row("Отброшено", "\(st.dropped)") }
                        // Эти два показываются только когда они не ноль: при нуле человеку от них
                        // ничего не требуется, а при не нуле требуется разное, и потому они врозь.
                        if st.queueDropped > 0 {
                            row("Не влезло в очередь", "\(st.queueDropped)")
                        }
                        if st.oversizeDropped > 0 {
                            row("Слишком крупные", "\(st.oversizeDropped)")
                        }
                    }
                }

                Section("Настройка") {
                    TextEditor(text: $conf)
                        .font(.system(.footnote, design: .monospaced))
                        .frame(minHeight: 180)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    Button("Сохранить") {
                        Task { await tunnel.save(conf: conf) }
                    }
                    .disabled(conf.isEmpty || conf == tunnel.confText)
                    Button("Открыть файл…") { showImporter = true }
                    if tunnel.status != .invalid {
                        Button("Удалить из системы", role: .destructive) {
                            Task { await tunnel.remove() }
                        }
                    }
                }

                Section("Новый ключ") {
                    if let k = newKey {
                        Text(k)
                            .font(.system(.footnote, design: .monospaced))
                            .textSelection(.enabled)
                        Text(publicOf(k))
                            .font(.system(.footnote, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                    Button("Создать пару ключей") {
                        newKey = try? XsteerGenerateKey()
                    }
                }

                if let e = tunnel.lastError {
                    Section {
                        Text(e).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Xsteer")
            .onAppear { if conf.isEmpty { conf = tunnel.confText } }
            .fileImporter(isPresented: $showImporter, allowedContentTypes: [.text, .json, .item]) { res in
                guard case let .success(url) = res else { return }
                let ok = url.startAccessingSecurityScopedResource()
                defer { if ok { url.stopAccessingSecurityScopedResource() } }
                if let t = try? String(contentsOf: url, encoding: .utf8) {
                    conf = t
                    Task { await tunnel.save(conf: t) }
                }
            }
        }
    }

    private var isOn: Bool {
        tunnel.status == .connected || tunnel.status == .connecting || tunnel.status == .reasserting
    }

    private var title: String {
        switch tunnel.status {
        case .connected: return "Подключено"
        case .connecting: return "Подключение"
        case .reasserting: return "Переподключение"
        case .disconnecting: return "Отключение"
        case .disconnected: return "Отключено"
        case .invalid: return "Настройка не сохранена"
        @unknown default: return "Неизвестно"
        }
    }

    private var color: Color {
        switch tunnel.status {
        case .connected: return .green
        case .connecting, .reasserting, .disconnecting: return .orange
        default: return .secondary
        }
    }

    private func publicOf(_ priv: String) -> String {
        (try? XsteerPublicKeyOf(priv)) ?? ""
    }

    private func row(_ k: String, _ v: String) -> some View {
        HStack {
            Text(k).foregroundStyle(.secondary)
            Spacer()
            Text(v).multilineTextAlignment(.trailing)
        }
        .font(.footnote)
    }

    private func bytes(_ n: UInt64) -> String {
        let f = ByteCountFormatter()
        f.countStyle = .binary
        return f.string(fromByteCount: Int64(n))
    }
}
