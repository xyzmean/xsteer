package net.xsteer.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import androidx.core.app.NotificationCompat
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.util.Log
import xsteer.Tunnel
import xsteer.Xsteer

/**
 * Служба, которая и есть туннель.
 *
 * РАЗДЕЛЕНИЕ ТРУДА С ЧАСТЬЮ НА GO. Здесь остаётся только то, что принадлежит платформе:
 * построение туннеля (адрес, маршруты, резолвер, MTU), уведомление и извещения о смене сети.
 * Протокол, шифрование, рукопожатие, разбор настройки и согласование MTU — целиком в Go.
 *
 * ЧЕМ ЭТО ПРОЩЕ iOS. Android отдаёт настоящий дескриптор устройства, а не объект с вызовами.
 * Значит пакеты не пересекают границу языков вовсе: их читает и пишет тот же код, что на обычном
 * Linux. Поэтому здесь нет ни очереди, ни склейки, ни счётчиков потерь — всё это на iOS нужно
 * ровно потому, что там дескриптора нет.
 */
class XsteerVpnService : VpnService() {

    private var tunnel: Tunnel? = null
    private var netCallback: ConnectivityManager.NetworkCallback? = null

    companion object {
        private const val TAG = "xsteer"
        private const val CHANNEL = "tunnel"
        private const val NOTIFY_ID = 1

        const val ACTION_DISCONNECT = "net.xsteer.android.DISCONNECT"

        /**
         * Состояние для интерфейса. Служба живёт в том же процессе, что и приложение, поэтому
         * переговоров между ними не нужно — в отличие от iOS, где расширение это отдельный
         * процесс и состояние приходится спрашивать сообщением.
         */
        @Volatile
        var running: Boolean = false
            private set

        @Volatile
        var lastError: String? = null
            internal set

        @Volatile
        private var current: Tunnel? = null

        /** Снимок состояния из Go, как есть в JSON. Пусто, пока туннель не поднят. */
        fun stateJson(): String? = current?.stateJSON()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            stopTunnel()
            stopSelf()
            return START_NOT_STICKY
        }
        val conf = Prefs(this).conf
        if (conf.isBlank()) {
            lastError = "Настройка не задана"
            stopSelf()
            return START_NOT_STICKY
        }
        startTunnel(conf)
        // START_NOT_STICKY нарочно: поднимать туннель заново без человека нельзя. Он мог
        // выключить его сам, и возвращать соединение против его воли — не наше дело.
        return START_NOT_STICKY
    }

    private fun startTunnel(conf: String) {
        stopTunnel()
        val t = Xsteer.newTunnel()
        t.setLogger { line -> Log.i(TAG, line ?: "") }

        // Разбор настройки — в Go, теми же проверками и с теми же отказами, что в консольной
        // половине. Повторять их здесь значило бы иметь два мнения о том, что такое правильная
        // настройка, и разойтись с ними при первой же правке формата.
        try {
            t.configure(conf)
        } catch (e: Exception) {
            fail("Настройка не разобрана: ${e.message}")
            return
        }

        val fd = try {
            establish(t)
        } catch (e: Exception) {
            fail("Туннель не поднялся: ${e.message}")
            return
        }
        if (fd < 0) {
            // Отказ здесь означает, что человек не дал разрешения или система его отозвала.
            fail("Система не дала поднять туннель")
            return
        }

        try {
            t.startFD(fd.toLong(), "tun0")
        } catch (e: Exception) {
            fail("Клиент не запустился: ${e.message}")
            return
        }

        tunnel = t
        current = t
        running = true
        lastError = null
        startForeground(NOTIFY_ID, notification(t.hubAddress()))
        watchNetwork()
        Log.i(TAG, "туннель поднят, хаб ${t.hubAddress()}:${t.hubPort()}")
    }

    /**
     * Строит туннель и отдаёт ГОТОВЫЙ дескриптор.
     *
     * Всё, что здесь стоит, приходит из Go: адрес, длина префикса, маршруты, резолвер и MTU.
     * Своего разбора настройки на Kotlin нет ни строки.
     */
    private fun establish(t: Tunnel): Int {
        val b = Builder()
        b.setSession("Xsteer")
        b.addAddress(t.address(), t.prefixLen().toInt())

        // MTU НИКОГДА не больше того, что туннель готов нести: путь данных читает пакеты окном
        // ровно такого размера и признака усечения не имеет, поэтому пакет крупнее пропал бы
        // целиком. Число приходит из Go уже зажатым.
        b.setMtu(t.mtu().toInt())

        for (cidr in t.includedRoutes().split(",")) {
            val parts = cidr.trim().split("/")
            if (parts.size != 2) continue
            val plen = parts[1].toIntOrNull() ?: continue
            b.addRoute(parts[0], plen)
        }

        for (dns in t.dnsServers().split(",")) {
            val s = dns.trim()
            if (s.isNotEmpty()) b.addDnsServer(s)
        }

        // СЕБЯ ИЗ ТУННЕЛЯ ИСКЛЮЧАЕМ, и это обязательно. Иначе соединение к хабу ушло бы в
        // собственный туннель, которого ещё нет, и подъём упёрся бы в таймаут. На iOS система
        // делает это сама, здесь — надо сказать.
        try {
            b.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.w(TAG, "не вышло исключить себя из туннеля: ${e.message}")
        }

        // Неблокирующий режим: контракт чтения — «когда пусто, сразу назад», и на блокирующем
        // дескрипторе путь данных перестал бы собирать пачки.
        b.setBlocking(false)

        val pfd = b.establish() ?: return -1
        // detachFd, а не getFd: дескриптор переходит в собственность части на Go, и закроет его
        // она. С getFd его закрыли бы дважды — второй раз уже чужой, переиспользованный номер, —
        // и проявилось бы это не здесь и не сразу.
        return pfd.detachFd()
    }

    private fun watchNetwork() {
        // Своё слежение за сетью в Go отключено нарочно: без netlink оно опрашивает адрес выхода
        // раз в пять секунд, а внутри туннеля адресом источника ядро может назвать адрес самого
        // туннеля. Правду о пути знает платформа.
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.i(TAG, "сеть сменилась — переподнимаю соединения")
                tunnel?.netChanged()
            }

            override fun onLost(network: Network) {
                tunnel?.netChanged()
            }
        }
        try {
            cm.registerNetworkCallback(NetworkRequest.Builder().build(), cb)
            netCallback = cb
        } catch (e: Exception) {
            Log.w(TAG, "слежение за сетью не завелось: ${e.message}")
        }
    }

    private fun stopTunnel() {
        netCallback?.let { cb ->
            try {
                getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
            } catch (e: Exception) {
                Log.w(TAG, "снятие слежения: ${e.message}")
            }
        }
        netCallback = null
        // Stop ждёт, пока клиент отдаст накопленное и закроет дескриптор. Он же его и закрывает:
        // дескриптор мы отдали в собственность части на Go через detachFd.
        tunnel?.stop()
        tunnel = null
        current = null
        running = false
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    private fun fail(msg: String) {
        Log.e(TAG, msg)
        lastError = msg
        running = false
        stopSelf()
    }

    override fun onRevoke() {
        // Система отозвала разрешение: человек включил другой VPN или отнял согласие.
        Log.i(TAG, "разрешение отозвано")
        stopTunnel()
        stopSelf()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    private fun notification(hub: String): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(
                CHANNEL,
                getString(R.string.channel_name),
                NotificationManager.IMPORTANCE_LOW,
            )
            // Без звука и без всплытия: это не событие, а полоска состояния.
            ch.setShowBadge(false)
            nm?.createNotificationChannel(ch)
        }

        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, XsteerVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE,
        )

        // NotificationCompat, а не Notification.Builder: второй в виде с каналом появился только
        // в двадцать шестом уровне, а приложение работает с двадцать четвёртого. Компилировалось
        // бы и так — а падало бы на телефоне, и только на старом.
        return NotificationCompat.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(hub)
            .setSmallIcon(R.drawable.ic_tunnel)
            .setOngoing(true)
            .setContentIntent(open)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .addAction(NotificationCompat.Action.Builder(0, "Отключить", stop).build())
            .build()
    }
}
