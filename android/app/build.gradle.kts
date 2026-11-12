plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.drafto.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.drafto.app"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    buildFeatures { compose = true }
    // Kotlin 2.0+: the Compose compiler version follows the Kotlin plugin
    // (org.jetbrains.kotlin.plugin.compose). composeOptions is 1.9-era and
    // incompatible with K2.

    packaging {
        resources { excludes += "/META-INF/{AL2.0,LGPL2.1}" }
    }

    // The gomobile AAR (drafto.aar) carries the Go core as JNI libs.
    // It is an optional build input: the CI job binds it before Gradle runs,
    // and android/core-go/build-core.sh produces it locally. When it is
    // absent the app still compiles (GoDraftoEngine resolves the binding by
    // reflection at runtime and EngineFactory falls back to FakeEngine).
    sourceSets["main"].jniLibs.srcDir("libs")
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.09.02")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.2")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    debugImplementation("androidx.compose.ui:ui-tooling")

    // gomobile binding (generated AAR), consumed only when present.
    implementation(fileTree("libs") { include("*.aar") })
}
