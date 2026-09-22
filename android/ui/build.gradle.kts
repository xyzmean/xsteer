@file:Suppress("UnstableApiUsage")

val pkg: String = providers.gradleProperty("xsteerPackageName").get()

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.legacy.kapt)
}

// Ключ подписи берётся из окружения, и это не удобство, а условие обновляемости: Android ставит
// новую версию поверх прежней только тогда, когда обе подписаны одним ключом, а отладочный ключ
// на чистом бегунке каждый раз новый. Нет ключа — подписываем отладочным, и страница установки
// говорит об этом прямо.
val keystorePath: String? = System.getenv("XSTEER_KEYSTORE")?.takeIf { it.isNotBlank() }

android {
    compileSdk = 36
    buildFeatures {
        buildConfig = true
        dataBinding = true
        viewBinding = true
    }
    namespace = pkg
    defaultConfig {
        applicationId = pkg
        minSdk = 24
        // Номер сборки — номер прогона, если он есть: Android ставит поверх уже стоящего только
        // то, у чего номер ВЫШЕ, и с постоянной единицей вторая установка молча не заменяла бы
        // первую.
        versionCode = (System.getenv("BUILD_NUMBER")
            ?: providers.gradleProperty("xsteerVersionCode").get()).toInt()
        versionName = providers.gradleProperty("xsteerVersionName").get()
        buildConfigField("int", "MIN_SDK_VERSION", minSdk.toString())
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
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
            isMinifyEnabled = true
            isShrinkResources = true
            // proguard-rules.pro рядом — в нём то, что нельзя выбрасывать: переходник gomobile
            // состоит из имён, по которым в библиотеку и обращаются.
            proguardFiles("proguard-android-optimize.txt", "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("xsteer") ?: signingConfigs.getByName("debug")
            packaging {
                resources {
                    excludes += "DebugProbesKt.bin"
                    excludes += "kotlin-tooling-metadata.json"
                    excludes += "META-INF/*.version"
                }
            }
        }
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }
    androidResources {
        generateLocaleConfig = true
    }
    lint {
        disable += "LongLogTag"
        warning += "MissingTranslation"
        warning += "ImpliedQuantity"
    }
}

dependencies {
    implementation(project(":tunnel"))
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.annotation)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.coordinatorlayout)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.fragment.ktx)
    implementation(libs.androidx.preference.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.google.material)
    implementation(libs.zxing.android.embedded)
    implementation(libs.kotlinx.coroutines.android)
    coreLibraryDesugaring(libs.desugarJdkLibs)
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.add("-Xlint:unchecked")
    options.isDeprecation = true
}
