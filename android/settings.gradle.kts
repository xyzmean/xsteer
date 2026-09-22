// Сборка приложения под Android.
//
// ПОЧЕМУ ЗДЕСЬ НАМНОГО ПРОЩЕ, ЧЕМ НА iOS. Android разрешает приложению поднять туннель без
// особых прав: достаточно объявить службу VpnService, и система сама спросит у человека
// разрешение при первом подключении. Ни платного участия, ни сертификатов, ни чужих профилей —
// файл .apk собирается и ставится как есть.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "xsteer"
include(":app")
