pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // Guardian Project's version-pinned signed native Tor Android AAR.
        maven { url = uri("https://raw.githubusercontent.com/guardianproject/gpmaven/master") }
    }
}
rootProject.name = "KtestAndroid"
include(":app")
