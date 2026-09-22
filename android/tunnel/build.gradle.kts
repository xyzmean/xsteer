@file:Suppress("UnstableApiUsage")

// Библиотека туннеля: разбор конфигурации, ключи и мост к половине на Go.
//
// ЧТО ЗДЕСЬ УБРАНО ПО СРАВНЕНИЮ С ИСХОДНЫМ ПРОЕКТОМ WireGuard, из которого взят этот код:
// сборка нативных библиотек через CMake (libwg-go, libwg, libwg-quick) и выкладка в Maven. Наша
// половина на Go приезжает готовым xsteer.aar — его собирает android/build-aar.sh через gomobile,
// и своего кода на C у нас нет вовсе.
import org.gradle.api.tasks.testing.logging.TestLogEvent

val pkg: String = providers.gradleProperty("xsteerPackageName").get()

plugins {
    alias(libs.plugins.android.library)
}

android {
    compileSdk = 36
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    namespace = "${pkg}.tunnel"
    defaultConfig {
        minSdk = 24
    }
    testOptions.unitTests.all {
        it.testLogging { events(TestLogEvent.PASSED, TestLogEvent.SKIPPED, TestLogEvent.FAILED) }
    }
    lint {
        disable += "LongLogTag"
        disable += "NewApi"
    }
}

dependencies {
    // Половина на Go: протокол, шифрование, рукопожатие, разбор настройки и согласование MTU.
    // Кладёт файл android/build-aar.sh.
    //
    // ТОЛЬКО ДЛЯ КОМПИЛЯЦИИ, и это не выбор: библиотека Android не имеет права зависеть от
    // лежащего рядом .aar — собранная из неё библиотека вышла бы без его классов, и Gradle такую
    // сборку прекращает («Direct local .aar file dependencies are not supported when building an
    // AAR»). Поэтому здесь только заголовки, а в приложение (:ui) тот же файл входит целиком.
    compileOnly(files("libs/xsteer.aar"))
    implementation(libs.androidx.annotation)
    implementation(libs.androidx.collection)
    compileOnly(libs.jsr305)
    testImplementation(libs.junit)
}
