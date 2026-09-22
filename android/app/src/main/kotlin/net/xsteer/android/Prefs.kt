package net.xsteer.android

import android.content.Context

/**
 * Где лежит настройка.
 *
 * ЧЕСТНО О ПРИВАТНОМ КЛЮЧЕ. Он есть в этом тексте, и защищён он только песочницей приложения:
 * читать файлы чужого приложения на Android нельзя, но на устройстве с открытым доступом к
 * системному разделу это перестаёт быть правдой. Убрать текст нельзя — человек обязан видеть и
 * править то, что он ввёл, — поэтому он и не копируется больше никуда.
 */
class Prefs(ctx: Context) {
    private val sp = ctx.getSharedPreferences("xsteer", Context.MODE_PRIVATE)

    var conf: String
        get() = sp.getString(KEY_CONF, "") ?: ""
        set(v) = sp.edit().putString(KEY_CONF, v).apply()

    private companion object {
        const val KEY_CONF = "conf"
    }
}
