plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.nishef.ktest"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.nishef.ktest"
        minSdk = 26
        targetSdk = 35
        versionCode = 2
        versionName = "0.1.1"
        ndk { abiFilters += setOf("armeabi-v7a", "arm64-v8a") }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

}

dependencies {
    // Built from the real ktest Go core; not a placeholder/mock.
    implementation(files("libs/mobilebridge.aar"))
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
