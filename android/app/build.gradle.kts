import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Dedicated preview signing is optional for local developers. The preview APK
// workflow requires it explicitly; partial configuration must never fall back
// to a new developer debug key. Production signing is configured separately.
val previewSigningEnv = listOf(
    "KTEST_PREVIEW_KEYSTORE_PATH", "KTEST_PREVIEW_KEYSTORE_PASSWORD",
    "KTEST_PREVIEW_KEY_ALIAS", "KTEST_PREVIEW_KEY_PASSWORD"
).associateWith { providers.environmentVariable(it).orNull }
val previewSigningEnabled = providers.environmentVariable("KTEST_REQUIRE_PREVIEW_SIGNING")
    .orNull == "true" || previewSigningEnv.values.any { it != null }
if (previewSigningEnabled) {
    require(previewSigningEnv.values.all { !it.isNullOrBlank() }) {
        "Preview signing requires KTEST_PREVIEW_KEYSTORE_PATH, KTEST_PREVIEW_KEYSTORE_PASSWORD, KTEST_PREVIEW_KEY_ALIAS and KTEST_PREVIEW_KEY_PASSWORD."
    }
    val keystore = File(previewSigningEnv.getValue("KTEST_PREVIEW_KEYSTORE_PATH")!!)
    require(keystore.isAbsolute && keystore.isFile) {
        "Preview signing requires an existing absolute PKCS12 keystore path."
    }
}

android {
    namespace = "com.nishef.ktest"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.nishef.ktest"
        // Pinned HEV 2.19.0 requires Android 10; do not override its manifest.
        minSdk = 29
        targetSdk = 35
        // Monotonic Android package revision; not a CPU architecture version.
        versionCode = 18
        versionName = "0.4.6-preview"
        // The default device build remains ARM. Explicit x86_64 selection is
        // for emulator validation against the same packaged upstream cores.
        ndk { abiFilters += (providers.gradleProperty("ktestAbis").orNull
            ?.split(",") ?: listOf("armeabi-v7a", "arm64-v8a")) }
    }

    if (previewSigningEnabled) {
        signingConfigs {
            create("preview") {
                storeFile = file(previewSigningEnv.getValue("KTEST_PREVIEW_KEYSTORE_PATH")!!)
                storeType = "PKCS12"
                storePassword = previewSigningEnv.getValue("KTEST_PREVIEW_KEYSTORE_PASSWORD")
                keyAlias = previewSigningEnv.getValue("KTEST_PREVIEW_KEY_ALIAS")
                keyPassword = previewSigningEnv.getValue("KTEST_PREVIEW_KEY_PASSWORD")
            }
        }
        buildTypes {
            getByName("debug") {
                signingConfig = signingConfigs.getByName("preview")
            }
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // The existing native cores are separate executables, invoked from the
    // read-only package nativeLibraryDir rather than writable app storage.
    packaging {
        jniLibs.useLegacyPackaging = true
        // Runtime hashes refer to the unmodified upstream executables.
        jniLibs.keepDebugSymbols += setOf(
            "**/libaether.so", "**/libpsiphon-tunnel-core.so", "**/liblyrebird.so", "**/libciadpi.so", "**/libxray.so"
        )
    }

}

dependencies {
    // Built from the real ktest Go core; not a placeholder/mock.
    implementation(files("libs/mobilebridge.aar"))
    // Transport adapter only; the KTest Go core owns routing/verification.
    // SHA-256 pinned and fetched only in a manually approved Android build.
    implementation(files("libs/hev-socks5-tunnel.aar"))
    val composeBom = platform("androidx.compose:compose-bom:2025.09.01")
    implementation(composeBom)
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
}
