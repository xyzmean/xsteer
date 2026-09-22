package net.xsteer.android

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import net.xsteer.android.databinding.ActivityMainBinding
import org.json.JSONObject
import xsteer.Xsteer

/**
 * Настройка, кнопка и состояние.
 *
 * ПОЧЕМУ ЗДЕСЬ НЕТ ПЕРЕГОВОРОВ СО СЛУЖБОЙ. Служба живёт в том же процессе, поэтому состояние
 * читается прямо из неё. На iOS так нельзя: там расширение — отдельный процесс, и состояние
 * приходится спрашивать сообщением.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var ui: ActivityMainBinding
    private lateinit var prefs: Prefs
    private val tick = Handler(Looper.getMainLooper())

    /**
     * Согласие на туннель спрашивает САМА система, а не мы: VpnService.prepare возвращает
     * намерение, которое надо показать. Согласие даётся один раз на приложение, поэтому при
     * втором подключении prepare вернёт null и диалога не будет.
     */
    private val consent = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { res ->
        if (res.resultCode == RESULT_OK) start() else show("Без разрешения туннель не поднять")
    }

    private val notifyPerm = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { /* отказ терпим: туннель работает и без уведомления, просто хуже видно */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ui = ActivityMainBinding.inflate(layoutInflater)
        setContentView(ui.root)
        prefs = Prefs(this)
        ui.conf.setText(prefs.conf)

        ui.save.setOnClickListener {
            prefs.conf = ui.conf.text.toString()
            show("Сохранено")
        }

        ui.toggle.setOnClickListener {
            if (XsteerVpnService.running) stop() else connect()
        }

        ui.genkey.setOnClickListener {
            val k = Xsteer.newKeys()
            try {
                k.generate()
            } catch (e: Exception) {
                show("Ключ не создался: ${e.message}")
                return@setOnClickListener
            }
            ui.keys.text = "приватный\n${k.privateKey()}\n\nпубличный\n${k.publicKey()}"
            ui.keys.visibility = android.view.View.VISIBLE
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notifyPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun connect() {
        if (ui.conf.text.isBlank()) {
            show("Сначала вставьте настройку")
            return
        }
        prefs.conf = ui.conf.text.toString()
        val intent = VpnService.prepare(this)
        if (intent != null) consent.launch(intent) else start()
    }

    private fun start() {
        ContextCompat.startForegroundService(
            this, Intent(this, XsteerVpnService::class.java),
        )
        refreshSoon()
    }

    private fun stop() {
        startService(
            Intent(this, XsteerVpnService::class.java)
                .setAction(XsteerVpnService.ACTION_DISCONNECT),
        )
        refreshSoon()
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    override fun onPause() {
        super.onPause()
        tick.removeCallbacksAndMessages(null)
    }

    private fun refreshSoon() {
        // Полсекунды: служба поднимается не мгновенно, и сразу после нажатия состояние ещё старое.
        tick.postDelayed({ refresh() }, 500)
    }

    private fun refresh() {
        tick.removeCallbacksAndMessages(null)
        val up = XsteerVpnService.running
        ui.toggle.text = if (up) "Отключить" else "Подключить"

        val err = XsteerVpnService.lastError
        if (!up && err != null) {
            ui.status.text = err
            ui.details.visibility = android.view.View.GONE
            return
        }

        ui.status.text = if (up) "Подключено" else "Отключено"
        val json = XsteerVpnService.stateJson()
        if (!up || json == null) {
            ui.details.visibility = android.view.View.GONE
        } else {
            ui.details.text = describe(json)
            ui.details.visibility = android.view.View.VISIBLE
        }
        if (up) tick.postDelayed({ refresh() }, 2000)
    }

    /** Снимок из Go в несколько строк. Секретов в нём нет ни одного — он собран из счётчиков. */
    private fun describe(json: String): String = try {
        val o = JSONObject(json)
        val mtu = if (o.optInt("mtu_confirmed") > 0) o.optInt("mtu_confirmed") else o.optInt("mtu")
        buildString {
            append("хаб        ").append(o.optString("hub")).append('\n')
            append("ключ хаба  ").append(o.optString("hub_key")).append('\n')
            append("соединений ").append(o.optInt("conns")).append('\n')
            append("MTU        ").append(mtu).append('\n')
            append("отправлено ").append(bytes(o.optLong("tx_bytes"))).append('\n')
            append("получено   ").append(bytes(o.optLong("rx_bytes")))
            val dropped = o.optLong("dropped")
            if (dropped > 0) append("\nотброшено  ").append(dropped)
        }
    } catch (e: Exception) {
        json
    }

    private fun bytes(n: Long): String = when {
        n >= 1L shl 30 -> "%.1f ГиБ".format(n.toDouble() / (1L shl 30))
        n >= 1L shl 20 -> "%.1f МиБ".format(n.toDouble() / (1L shl 20))
        n >= 1L shl 10 -> "%.1f КиБ".format(n.toDouble() / (1L shl 10))
        else -> "$n Б"
    }

    private fun show(msg: String) {
        com.google.android.material.snackbar.Snackbar
            .make(ui.root, msg, com.google.android.material.snackbar.Snackbar.LENGTH_LONG)
            .show()
    }
}
