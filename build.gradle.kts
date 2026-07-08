plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.parcelize) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.ksp) apply false
    alias(libs.plugins.hilt) apply false
    id("org.jetbrains.dokka") version "2.2.0"
}

subprojects {
    pluginManager.withPlugin("com.android.library") {
        apply(plugin = "org.jetbrains.dokka")
    }
    pluginManager.withPlugin("com.android.application") {
        apply(plugin = "org.jetbrains.dokka")
    }
}

dependencies {
    dokka(project(":app"))
    dokka(project(":pgp-engine"))
    dokka(project(":data"))
    dokka(project(":encoding"))
    dokka(project(":api-client"))
}

dokka {
    dokkaPublications.html {
        moduleName.set("PGP Shield")
        moduleVersion.set(
            providers.gradleProperty("VERSION_NAME").orElse("1.0.0-alpha"),
        )
        outputDirectory.set(layout.buildDirectory.dir("dokka/html"))
    }
}
