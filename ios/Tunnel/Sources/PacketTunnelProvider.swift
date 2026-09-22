import Foundation
import NetworkExtension
import OSLog
import Xsteer

/// Расширение, которое и есть туннель.
///
/// НА iOS ТРАФИК НЕСЁТ ТОЛЬКО ОНО. Приложение-контейнер не может ни читать пакеты, ни писать их:
/// оно лишь заводит настройку в системе и нажимает «включить». Всё, что ниже, работает в отдельном
/// процессе с жёстким пределом памяти около пятнадцати мегабайт — отсюда и осторожность с
/// размерами очередей (см. queueLen в mobile/device.go).
///
/// РАЗДЕЛЕНИЕ ТРУДА С ЧАСТЬЮ НА GO. Здесь остаётся ровно то, что принадлежит платформе: настройки
/// туннеля (адрес, маска, маршруты, резолвер, MTU), чтение и запись пакетов через packetFlow и
/// извещения о смене сети. Протокол, шифрование, рукопожатие и согласование MTU — целиком в Go,
/// и ни одна строка этого не повторяется здесь.
class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = Logger(subsystem: "com.xyzmean.xsteer", category: "tunnel")
    private let tunnel = XsteerNewTunnel()!
    private var sink: Sink?
    private var pathMonitor: NWPathMonitorBox?

    override func startTunnel(options: [String: NSObject]?) async throws {
        // Настройка приходит в providerConfiguration, а не через общую группу приложений.
        // Группа — это отдельное право в профиле подписи, и чем меньше прав нужно профилю, тем
        // меньше того, что может не выдаться.
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let conf = proto.providerConfiguration?["conf"] as? String, !conf.isEmpty
        else {
            throw TunnelError.noConfiguration
        }

        let bridgeLog = BridgeLogger(log: log)
        tunnel.setLogger(bridgeLog)

        // Разбор настройки — в Go, тем же кодом и с теми же отказами, что в консольной половине.
        // Повторять проверки здесь значило бы иметь два разных мнения о том, что такое правильная
        // настройка, и расходиться с ними при первой же правке формата.
        do {
            try tunnel.configure(conf)
        } catch {
            log.error("настройка не разобрана: \(error.localizedDescription, privacy: .public)")
            throw error
        }

        // Адрес хаба разрешён и проверен в Go; здесь он нужен только для журнала.
        log.info("хаб \(self.tunnel.hubAddress(), privacy: .public):\(self.tunnel.hubPort())")

        try await setTunnelNetworkSettings(makeSettings())

        let sink = Sink(flow: packetFlow, log: log)
        self.sink = sink
        // Имя отдаётся ради журнала и снимка состояния: система своего интерфейса наружу не
        // называет, а «utun» без номера честнее выдуманного номера.
        try tunnel.start(sink, devName: "utun")

        startReading()
        startWatchingPath()
        log.info("туннель поднят")
    }

    override func stopTunnel(with reason: NEProviderStopReason) async {
        log.info("остановка: причина \(reason.rawValue)")
        pathMonitor?.cancel()
        pathMonitor = nil
        // Stop ждёт, пока клиент отдаст накопленное и закроет устройство. Возврат из stopTunnel
        // раньше означал бы убийство процесса посреди этой уборки.
        tunnel.stop()
        sink = nil
    }

    /// Приложение спрашивает состояние: единственный канал между ним и расширением, не требующий
    /// общей группы.
    override func handleAppMessage(_ messageData: Data) async -> Data? {
        guard let req = String(data: messageData, encoding: .utf8) else { return nil }
        switch req {
        case "state":
            return tunnel.stateJSON().data(using: .utf8)
        default:
            return nil
        }
    }

    override func sleep() async {
        // Ничего не останавливаем: соединение переживает засыпание, а если не переживёт —
        // пробуждение всё равно принесёт извещение о смене пути.
        log.debug("сон")
    }

    override func wake() {
        log.debug("пробуждение")
        tunnel.netChanged()
    }

    // MARK: - настройки туннеля

    /// Собирает NEPacketTunnelNetworkSettings из разобранной настройки.
    ///
    /// Всё, что здесь стоит, приходит из Go, а не из своего разбора: адрес, маска, маршруты,
    /// резолвер и MTU. MTU при этом никогда не больше того, что туннель готов нести (MaxMTU в
    /// mobile): путь данных читает пакеты окном такого размера и признака усечения не имеет, так
    /// что более крупный пакет был бы выброшен целиком — «мелкое ходит, крупное пропадает».
    private func makeSettings() -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: tunnel.hubAddress())

        let ipv4 = NEIPv4Settings(addresses: [tunnel.address()], subnetMasks: [tunnel.netmask()])
        let cidrs = tunnel.includedRoutes().split(separator: ",").map(String.init)
        ipv4.includedRoutes = cidrs.compactMap { Self.route(fromCIDR: $0) }
        if ipv4.includedRoutes?.isEmpty ?? true {
            // Пустой список означал бы туннель, в который ничего не заворачивается, то есть
            // молча неработающий. Лучше отказать явно, но отказать здесь нечем — поэтому
            // подразумевается то же, что подразумевает сама настройка без AllowedIPs: ничего.
            ipv4.includedRoutes = []
        }
        // Адрес хаба ИСКЛЮЧАЕТСЯ из туннеля всегда, даже при маршруте 0.0.0.0/0. Иначе соединение
        // расширения к хабу ушло бы в собственный туннель, которого ещё нет, и подъём упёрся бы в
        // таймаут. Система трафик провайдера в его туннель и так не заворачивает, но полагаться на
        // это без нужды незачем: явное исключение стоит одну строку.
        if let hub = Self.hostRoute(tunnel.hubAddress()) {
            ipv4.excludedRoutes = [hub]
        }
        settings.ipv4Settings = ipv4

        let dns = tunnel.dnsServers().split(separator: ",").map(String.init).filter { !$0.isEmpty }
        if !dns.isEmpty {
            let s = NEDNSSettings(servers: dns)
            // Пустой список правил соответствия значит «этот резолвер для всех имён». Без него
            // система оставила бы резолвер провайдера, и запросы ушли бы мимо туннеля.
            s.matchDomains = [""]
            settings.dnsSettings = s
        }

        settings.mtu = NSNumber(value: tunnel.mtu())
        return settings
    }

    private static func route(fromCIDR s: String) -> NEIPv4Route? {
        let parts = s.split(separator: "/")
        guard parts.count == 2, let plen = Int(parts[1]), plen >= 0, plen <= 32 else { return nil }
        return NEIPv4Route(destinationAddress: String(parts[0]), subnetMask: mask(plen))
    }

    private static func hostRoute(_ addr: String) -> NEIPv4Route? {
        guard !addr.isEmpty else { return nil }
        return NEIPv4Route(destinationAddress: addr, subnetMask: "255.255.255.255")
    }

    private static func mask(_ plen: Int) -> String {
        if plen == 0 { return "0.0.0.0" }
        let v = UInt32.max << (32 - UInt32(plen))
        return "\(v >> 24 & 255).\(v >> 16 & 255).\(v >> 8 & 255).\(v & 255)"
    }

    // MARK: - пакеты

    /// Забирает пакеты у системы и отдаёт их в туннель.
    ///
    /// Следующий запрос уходит СРАЗУ после передачи предыдущей порции: readPackets отдаёт по
    /// одному вызову за раз, и пауза между вызовами — это пауза в исходящем трафике.
    private func startReading() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            for p in packets {
                self.tunnel.inject(p)
            }
            self.startReading()
        }
    }

    private func startWatchingPath() {
        // Своё слежение за сетью в Go отключено нарочно (NoNetWatch): там оно сводится к опросу
        // адреса выхода раз в пять секунд, а внутри расширения адресом источника ядро может
        // назвать адрес самого туннеля — и опрос решал бы, что сеть сменилась, каждые пять секунд.
        // Правду о пути знает платформа, и вот она.
        pathMonitor = NWPathMonitorBox { [weak self] in
            self?.log.info("путь сменился — переподнимаю соединения")
            self?.tunnel.netChanged()
        }
    }

    enum TunnelError: LocalizedError {
        case noConfiguration
        var errorDescription: String? {
            switch self {
            case .noConfiguration: return "В настройке туннеля нет конфигурации xsteer"
            }
        }
    }
}

/// Получатель пакетов из туннеля.
///
/// СКЛЕЙКА ЖИВЁТ ЗДЕСЬ, А НЕ В GO, и это не вкус. Переход через границу gomobile стоит около
/// микросекунды, так что отдавать по одному пакету дорого; но накапливать на стороне Go и ждать
/// вызова Flush нельзя — входящий путь режима потока (единственного, который работает на iOS) не
/// зовёт Flush вообще, и последний пакет всплеска пролежал бы в буфере навсегда.
///
/// Поэтому признак конца всплеска берётся у платформы: пакеты копятся, а отдача назначается на
/// следующий виток очереди. Виток наступит обязательно и без чьей-либо доброй воли.
/// ПРО ИМЯ ПРОТОКОЛА. gomobile выносит интерфейс Go сразу двумя сущностями: протоколом
/// (для того, кто его реализует здесь) и одноимённым классом (обёрткой над значением,
/// реализованным в Go). Когда в Objective-C класс и протокол зовутся одинаково, Swift
/// переименовывает протокол, приписывая Protocol, — поэтому здесь XsteerPacketSinkProtocol, а не
/// XsteerPacketSink. С последним компилятор говорит «multiple inheritance from classes».
final class Sink: NSObject, XsteerPacketSinkProtocol {
    private let flow: NEPacketTunnelFlow
    private let log: Logger
    private let queue = DispatchQueue(label: "com.xyzmean.xsteer.sink")
    private var packets: [Data] = []
    private var protocols: [NSNumber] = []
    private var scheduled = false

    /// Предел набора. Не про память, а про задержку: очень быстрый поток иначе копил бы пакеты до
    /// конца витка, а виток при полной загрузке процессора может и затянуться.
    private let maxBatch = 64

    init(flow: NEPacketTunnelFlow, log: Logger) {
        self.flow = flow
        self.log = log
        super.init()
    }

    func writePacket(_ p: Data?, ipv6: Bool) {
        guard let p, !p.isEmpty else { return }
        queue.async {
            self.packets.append(p)
            self.protocols.append(NSNumber(value: ipv6 ? AF_INET6 : AF_INET))
            if self.packets.count >= self.maxBatch {
                self.deliver()
                return
            }
            guard !self.scheduled else { return }
            self.scheduled = true
            self.queue.async { self.deliver() }
        }
    }

    func flush() {
        queue.async { self.deliver() }
    }

    /// Зовётся только на своей очереди.
    private func deliver() {
        scheduled = false
        guard !packets.isEmpty else { return }
        let p = packets, pr = protocols
        packets.removeAll(keepingCapacity: true)
        protocols.removeAll(keepingCapacity: true)
        flow.writePackets(p, withProtocols: pr)
    }
}

/// Переходник журнала. Обязан быть потокобезопасным: клиент пишет в журнал из подъёма, из
/// слежения за сетью и из каждого соединения одновременно, без всякой синхронизации со своей
/// стороны. Logger из OSLog таким и является.
final class BridgeLogger: NSObject, XsteerLoggerProtocol {
    private let log: Logger
    init(log: Logger) {
        self.log = log
        super.init()
    }

    func log(_ line: String?) {
        guard let line else { return }
        // privacy: .public нарочно: в журнале клиента секретов нет по построению — его печатает
        // тот же код, что снимок состояния, а до приватного ключа оттуда не дотянуться. Без этого
        // указания система заменила бы всё на <private>, и журнал перестал бы быть журналом.
        self.log.info("\(line, privacy: .public)")
    }
}
