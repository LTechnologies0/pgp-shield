plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.parcelize)
    alias(libs.plugins.ksp)
    alias(libs.plugins.hilt)
}

android {
    namespace = "ltechnologies.onionphone.pgpshield"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        applicationId = "ltechnologies.onionphone.pgpshield"
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
        versionCode = 1
        versionName = "1.0.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        debug {
            isDebuggable = true
            val debugEndpoint = project.findProperty("debugAgentEndpoint")?.toString().orEmpty()
            buildConfigField("String", "DEBUG_AGENT_ENDPOINT", "\"$debugEndpoint\"")
            buildConfigField("String", "DEBUG_AGENT_SESSION", "\"${project.findProperty("debugAgentSession") ?: ""}\"")
        }
        release {
            isMinifyEnabled = true
            isDebuggable = false
            buildConfigField("String", "DEBUG_AGENT_ENDPOINT", "\"\"")
            buildConfigField("String", "DEBUG_AGENT_SESSION", "\"\"")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
                rootProject.file("gradle/privacy-logging.pro"),
            )
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
        aidl = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
        }
    }
}
apply(from = rootProject.file("gradle/abi-release.gradle"))

dependencies {
    implementation(project(":pgp-engine"))
    implementation(project(":data"))
    implementation(project(":encoding"))
    implementation(project(":api-client"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.navigation.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material3.adaptive.navigation.suite)
    implementation("androidx.compose.material:material-icons-extended")
    implementation(libs.hilt.android)
    implementation(libs.hilt.navigation.compose)
    ksp(libs.hilt.compiler)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.timber)
    implementation(libs.zxing.core)

    debugImplementation("com.squareup.leakcanary:leakcanary-android:2.14")
    debugImplementation(libs.androidx.compose.ui.test.manifest)

    testImplementation(libs.junit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(project(":pgp-engine"))
}

apply(from = rootProject.file("gradle/release-signing.gradle"))
