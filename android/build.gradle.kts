// Top-level build file. Plugin versions are declared here and applied per-module.
plugins {
    id("com.android.application") version "8.5.2" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    // Kotlin 2.0+ ships the Compose compiler as a separate Gradle plugin.
    // It must match the Kotlin version exactly.
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
}
