import Foundation
import Network

/// Сторож пути: извещает, когда сеть под туннелем сменилась.
///
/// ЗАЧЕМ ОН НУЖЕН ИМЕННО ЗДЕСЬ. У клиента на Go есть своё слежение, но там, где нет netlink, оно
/// сводится к опросу адреса выхода раз в пять секунд. Внутри расширения это не просто бесполезно,
/// а вредно: адресом источника ядро может назвать адрес самого туннеля, и опрос решит, что сеть
/// сменилась, — то есть переподнимет все соединения, и так каждые пять секунд. Поэтому своё
/// слежение выключено (NoNetWatch), а правду сообщает платформа.
///
/// ПОЧЕМУ ПО ИНТЕРФЕЙСУ, А НЕ ПО ДОСТУПНОСТИ. Переход с Wi-Fi на сотовую связь меняет адрес
/// выхода, и соединение к хабу после него мертво, хотя доступность всё время была «есть». Поэтому
/// сравнивается набор интерфейсов, а не флаг satisfied: иначе самый частый случай — человек вышел
/// из дома — остался бы незамеченным до таймаута.
final class NWPathMonitorBox {
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "com.xyzmean.xsteer.path")
    private var last: String?
    private let onChange: () -> Void

    init(onChange: @escaping () -> Void) {
        self.onChange = onChange
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let key = Self.key(of: path)
            // Первый вызов приходит сразу после старта и описывает ту же сеть, на которой туннель
            // только что поднялся: переподнимать соединения на нём незачем.
            if self.last == nil {
                self.last = key
                return
            }
            guard self.last != key else { return }
            self.last = key
            self.onChange()
        }
        monitor.start(queue: queue)
    }

    func cancel() {
        monitor.cancel()
    }

    /// Ключ пути: доступность плюс перечень интерфейсов, кроме своего же туннеля.
    ///
    /// Свой туннель исключается обязательно: он появляется и исчезает вместе с нами, и без этого
    /// исключения его собственное появление читалось бы как смена сети.
    private static func key(of path: NWPath) -> String {
        let kinds = path.availableInterfaces
            .filter { $0.type != .other }
            .map { "\($0.type)" }
            .sorted()
            .joined(separator: "+")
        return "\(path.status)|\(kinds)"
    }
}
