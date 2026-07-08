plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "ltechnologies.onionphone.pgpshield.api.stub"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}

dependencies {
    api(project(":api-client"))
    implementation(libs.kotlinx.coroutines.core)

    testImplementation(libs.junit)
}
