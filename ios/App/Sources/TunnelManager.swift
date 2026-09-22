import Combine
import Foundation
import NetworkExtension

/// Настройка туннеля в системе и кнопка «включить».
///
/// ПОЧЕМУ ЭТО ЖИВЁТ В ПРИЛОЖЕНИИ. Заводить и менять настройку VPN умеет только приложение, а не
/// расширение: у расширения нет ни NETunnelProviderManager, ни права его звать. Расширение же,
/// наоборот, единственное, кто видит пакеты. Разделение навязано платформой, а не выбрано.
@MainActor
final class TunnelManager: ObservableObject {
    @Published var status: NEVPNStatus = .invalid
    @Published var lastError: String?
    /// Снимок состояния из расширения. Пусто, пока туннель не поднят.
    @Published var state: TunnelState?

    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?
    private var pollTask: Task<Void, Never>?

    private let confKey = "xsteer.conf"

    init() {
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: nil, queue: .main
        ) { [weak self] note in
            guard let conn = note.object as? NEVPNConnection else { return }
            Task { @MainActor in self?.status = conn.status }
        }
    }

    /// Настройка, которую человек ввёл. Хранится в UserDefaults приложения, а не в связке ключей.
    ///
    /// ЧЕСТНО О ТОМ, ГДЕ ЛЕЖИТ ПРИВАТНЫЙ КЛЮЧ. Приватный ключ есть и в этом тексте, и в
    /// providerConfiguration, куда его кладёт система при сохранении настройки VPN. Второе
    /// защищено связкой ключей самой системы, первое — только песочницей приложения. Убрать
    /// первое нельзя: человек обязан видеть и править то, что он ввёл. Поэтому текст и не
    /// копируется больше никуда.
    var confText: String {
        get { UserDefaults.standard.string(forKey: confKey) ?? "" }
        set { UserDefaults.standard.set(newValue, forKey: confKey) }
    }

    func load() async {
        do {
            let all = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = all.first
            status = manager?.connection.status ?? .invalid
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Сохраняет настройку в системе. Первый вызов покажет человеку запрос на добавление VPN.
    func save(conf: String) async {
        confText = conf
        let m = manager ?? NETunnelProviderManager()
        let proto = (m.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        // serverAddress система показывает в настройках VPN. Адрес хаба сюда не подставляется:
        // он появится, только когда настройка разобрана, а разбирает её расширение.
        proto.serverAddress = "xsteer"
        proto.providerBundleIdentifier = "com.xyzmean.xsteer.tunnel"
        proto.providerConfiguration = ["conf": conf]
        m.protocolConfiguration = proto
        m.localizedDescription = "Xsteer"
        m.isEnabled = true
        do {
            try await m.saveToPreferences()
            // Перечитать обязательно: после сохранения у объекта в памяти нет ссылки на
            // соединение, и connection.status врал бы «invalid» до перезапуска приложения.
            try await m.loadFromPreferences()
            manager = m
            status = m.connection.status
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
    }

    func start() async {
        guard let m = manager else {
            lastError = "Сначала сохраните настройку"
            return
        }
        do {
            try m.connection.startVPNTunnel()
            lastError = nil
            startPolling()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
        pollTask?.cancel()
        pollTask = nil
        state = nil
    }

    func remove() async {
        guard let m = manager else { return }
        do {
            try await m.removeFromPreferences()
            manager = nil
            status = .invalid
            state = nil
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Опрос состояния у расширения раз в две секунды.
    ///
    /// Через sendProviderMessage, а не через общую группу приложений: группа — это отдельное право
    /// в профиле подписи, и чем меньше прав нужно, тем меньше того, что может не выдаться.
    private func startPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.pollOnce()
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    private func pollOnce() async {
        guard let session = manager?.connection as? NETunnelProviderSession,
              status == .connected || status == .reasserting
        else { return }
        guard let req = "state".data(using: .utf8) else { return }
        let data: Data? = await withCheckedContinuation { cont in
            do {
                try session.sendProviderMessage(req) { cont.resume(returning: $0) }
            } catch {
                cont.resume(returning: nil)
            }
        }
        guard let data, let st = try? JSONDecoder().decode(TunnelState.self, from: data) else { return }
        state = st
    }
}

/// Снимок состояния из расширения. Поля — те же, что печатает консольная половина, плюс два
/// счётчика самого моста.
struct TunnelState: Decodable {
    var up: Bool = false
    var conns: Int = 0
    var mtu: Int = 0
    var mtuConfirmed: Int = 0
    var hub: String = ""
    var hubKey: String = ""
    var handshakeAge: Int = -1
    var txPackets: UInt64 = 0
    var txBytes: UInt64 = 0
    var rxPackets: UInt64 = 0
    var rxBytes: UInt64 = 0
    var dropped: UInt64 = 0
    var queueDropped: UInt64 = 0
    var oversizeDropped: UInt64 = 0

    enum CodingKeys: String, CodingKey {
        case up, conns, mtu
        case mtuConfirmed = "mtu_confirmed"
        case hub
        case hubKey = "hub_key"
        case handshakeAge = "handshake_age"
        case txPackets = "tx_packets"
        case txBytes = "tx_bytes"
        case rxPackets = "rx_packets"
        case rxBytes = "rx_bytes"
        case dropped
        case queueDropped = "queue_dropped"
        case oversizeDropped = "oversize_dropped"
    }
}
