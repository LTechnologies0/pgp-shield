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
    }
}

rootProject.name = "pgp-shield"

include(
    ":app",
    ":pgp-engine",
    ":encoding",
    ":data",
    ":api-client",
    ":api-client-stub",
)
