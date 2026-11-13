package com.drafto.app.core

import android.content.Context
import android.util.Log
import java.io.File

/**
 * Selects the engine implementation for the app.
 *
 * The production engine is [GoDraftoEngine], which persists to SQLite through
 * the Go core. It requires the gomobile binding (`drafto.aar`) on the
 * classpath — produced by the CI job or `android/core-go/build-core.sh`.
 *
 * When the binding is absent (plain IDE preview, or a build that did not bind
 * first) we fall back to [FakeEngine]. The fallback is **explicit and logged**:
 * silent degradation to ephemeral storage is what made the earlier Android
 * integration look "done" while dropping every write.
 */
object EngineFactory {

    private const val TAG = "EngineFactory"

    /** Name of the SQLite file inside the app's private storage. */
    private const val DB_NAME = "drafto.db"

    /**
     * Builds the engine for this process.
     *
     * @param context application context (required by the Go runtime).
     * @param preferGo set to false to force the in-memory engine (UI preview,
     *   instrumented tests that do not want persistence).
     */
    fun create(context: Context, preferGo: Boolean = true): DraftoEngine {
        if (!preferGo) {
            Log.i(TAG, "using FakeEngine (preferGo=false)")
            return FakeEngine()
        }
        if (!GoDraftoEngine.isAvailable()) {
            Log.w(
                TAG,
                "gomobile binding ($BINDING) not on the classpath — falling back to " +
                    "FakeEngine. Writes will NOT persist. Build the AAR with " +
                    "android/core-go/build-core.sh or run the CI Android job.",
            )
            return FakeEngine()
        }
        return runCatching {
            GoDraftoEngine.openAt(context, databasePath(context))
        }.getOrElse { e ->
            Log.e(TAG, "GoDraftoEngine failed to open; falling back to FakeEngine", e)
            FakeEngine()
        }
    }

    /** Absolute path of the SQLite database in app-private storage. */
    fun databasePath(context: Context): String {
        val dir: File = context.applicationContext.getDatabasePath(DB_NAME).parentFile
            ?: context.applicationContext.filesDir
        if (!dir.exists()) dir.mkdirs()
        return File(dir, DB_NAME).absolutePath
    }

    /** True when the real (persistent) engine can be constructed. */
    fun isPersistentAvailable(): Boolean = GoDraftoEngine.isAvailable()

    private const val BINDING = "go.drafto.Core"
}
