plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

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

    buildTypes {
        release {
            // Сжатие кода выключено НАРОЧНО. Библиотека из Go приходит готовым .so, а её
            // переходник на Java состоит из имён, по которым в неё и обращаются: сжатие
            // выбросило бы их, и отказ был бы не при сборке, а при первом подключении.
            isMinifyEnabled = false
            // Подпись отладочным ключом, чтобы .apk из сборки ставился без лишних шагов.
            // Своей подписи здесь не нужно: на Android ничего, кроме разрешения на установку
            // из этого источника, от человека не требуется.
            signingConfig = signingConfigs.getByName("debug")
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
}
