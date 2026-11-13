package com.drafto.app

import android.app.Application
import com.drafto.app.core.DraftoEngine
import com.drafto.app.core.EngineFactory

/**
 * Application entry point. Owns the process-wide [DraftoEngine].
 *
 * The engine is created with the application context so the Go core can open
 * its SQLite database in app-private storage. When the gomobile binding is not
 * on the classpath the factory logs the reason and returns the in-memory
 * engine (see [EngineFactory]).
 */
class DraftoApp : Application() {
    lateinit var engine: DraftoEngine
        private set

    /** True when [engine] persists data across process restarts. */
    var isPersistent: Boolean = false
        private set

    override fun onCreate() {
        super.onCreate()
        engine = EngineFactory.create(applicationContext)
        isPersistent = EngineFactory.isPersistentAvailable()
    }
}
