plugins {
    id("com.android.application")
}

android {
    namespace = "com.nishef.ktest.vpnprobe"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.nishef.ktest.vpnprobe"
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
