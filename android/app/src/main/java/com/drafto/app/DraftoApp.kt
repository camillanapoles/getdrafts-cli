package com.drafto.app

import android.app.Application
import com.drafto.app.core.DraftoEngine
import com.drafto.app.core.EngineFactory

/** Application entry point. Holds the process-wide [DraftoEngine]. */
class DraftoApp : Application() {
    lateinit var engine: DraftoEngine
        private set

    override fun onCreate() {
        super.onCreate()
        // Default to FakeEngine (preview). Swap for GoDraftoEngine after gomobile.
        engine = EngineFactory.create()
    }
}
