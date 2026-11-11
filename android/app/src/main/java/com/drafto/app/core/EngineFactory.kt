package com.drafto.app.core

/**
 * Returns the engine the app should use.
 *
 * Defaults to [FakeEngine] so the UI is previewable without a gomobile build.
 * Switch to [GoDraftoEngine] after running `android/core-go/build-core.sh` and
 * wiring the generated `go.drafto.Core` binding.
 */
object EngineFactory {
    fun create(): DraftoEngine = FakeEngine()
}
