plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Ключ подписи берётся из окружения, и это не удобство, а условие обновляемости.
//
// Android ставит новую версию ПОВЕРХ прежней только тогда, когда обе подписаны одним ключом. У
// отладочного ключа, который Gradle заводит сам, на чистом бегунке каждый раз НОВЫЙ отпечаток —
// значит каждая сборка получалась бы отдельным приложением, и обновление требовало бы удалить
// прежнее вместе с настройкой. Поэтому: есть ключ — подписываем им, нет — подписываем отладочным
// и говорим об этом прямо на странице установки.
val keystorePath: String? = System.getenv("XSTEER_KEYSTORE")?.takeIf { it.isNotBlank() }

android {
    namespace = "net.xsteer.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "net.xsteer.android"
        minSdk = 24
        targetSdk = 35
        versionCode = (System.getenv("BUILD_NUMBER") ?: "1").toInt()
        versionName = "0.1.0"
    }

    signingConfigs {
        if (keystorePath != null) {
            create("xsteer") {
                storeFile = file(keystorePath)
                storePassword = System.getenv("XSTEER_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("XSTEER_KEY_ALIAS") ?: "xsteer"
                keyPassword = System.getenv("XSTEER_KEY_PASSWORD")
                    ?: System.getenv("XSTEER_KEYSTORE_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            // Сжатие кода выключено НАРОЧНО. Библиотека из Go приходит готовым .so, а её
            // переходник на Java состоит из имён, по которым в неё и обращаются: сжатие
            // выбросило бы их, и отказ был бы не при сборке, а при первом подключении.
            isMinifyEnabled = false
            // Ключ проекта, если он задан; иначе отладочный — .apk из любой сборки обязан
            // ставиться без лишних шагов, а неподписанный не ставится вовсе.
            signingConfig = signingConfigs.findByName("xsteer") ?: signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        viewBinding = true
    }

    packaging {
        // Библиотека из Go уже без отладочных таблиц (-ldflags "-s -w"), пусть остаётся как есть.
        jniLibs.keepDebugSymbols += "**/libgojni.so"
    }
}

dependencies {
    // Библиотека, собранная gomobile: android/app/libs/xsteer.aar. Кладёт её build-aar.sh.
    implementation(files("libs/xsteer.aar"))
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    // Чтение QR камерой. Своего кода распознавания здесь нет и не будет: это отдельная задача,
    // и написанная наспех она отказывает молча — «код не читается», а почему, неизвестно.
    // Библиотека своя у камеры и сама спрашивает разрешение при первом запуске.
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
}
