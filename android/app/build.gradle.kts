plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.nishef.ktest"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.nishef.ktest"
        // Pinned HEV 2.19.0 requires Android 10; do not override its manifest.
        minSdk = 29
        targetSdk = 35
        versionCode = 4
        versionName = "0.3.0"
        // The default device build remains ARM. Explicit x86_64 selection is
        // for emulator validation against the same packaged upstream cores.
        ndk { abiFilters += (providers.gradleProperty("ktestAbis").orNull
            ?.split(",") ?: listOf("armeabi-v7a", "arm64-v8a")) }
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
            "**/libaether.so", "**/libpsiphon-tunnel-core.so", "**/liblyrebird.so", "**/libciadpi.so"
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
