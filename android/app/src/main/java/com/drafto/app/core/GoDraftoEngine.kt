package com.drafto.app.core

/**
 * Reflection-based adapter over the gomobile-generated AAR.
 *
 * ## Why reflection
 *
 * The AAR (`drafto.aar`) is produced by the CI (`gomobile bind`) and by
 * `android/core-go/build-core.sh`. It is **not** in the repository, so the app
 * must compile without it. A compile-time dependency on the generated
 * `go.drafto.Core` class would break every local build and every CI run that
 * does not bind first.
 *
 * Reflection keeps the build hermetic: the code compiles always, and the real
 * engine activates only when the binding is actually on the classpath. When it
 * is missing we fail fast with a clear message instead of silently falling
 * back to fake storage.
 *
 * ## Contract with the AAR
 *
 * `gomobile bind` emits a Java/Kotlin class `go.drafto.Core` with:
 *   - constructors: `Core()` (in-memory) and, from our boundary, `NewAt`-based
 *     construction is exposed as a package function — see [openAt].
 *   - methods mirroring the `//export` functions: `CreateDraft`, `GetDraft`,
 *     `QueryDrafts`, `SetFlagged`, `ArchiveDraft`, `TrashDraft`,
 *     `ReplaceDraft`, `AddTags`, `RunAction`, `ListTags`, `Counts`,
 *     `RegisterAction`, `Close`.
 *   - `go.Seq.setContext(android.content.Context)` must be called once so the
 *     Go runtime can reach the Android context (files dir, etc).
 *
 * Every call is wrapped so a missing/renamed member produces an actionable
 * error instead of a `NoSuchMethodException` buried in a stack trace.
 */
class GoDraftoEngine private constructor(
    private val binding: Any,
    private val databasePath: String,
) : DraftoEngine {

    // ---- Resolution helpers -------------------------------------------------

    private val bindingClass: Class<*> = binding.javaClass

    private fun method(name: String, vararg arity: Int): java.lang.reflect.Method {
        val candidates = bindingClass.methods.filter { it.name == name && it.parameterCount in arity }
        return candidates.firstOrNull()
            ?: error(
                "GoDraftoEngine: '$name' (arity ${arity.joinToString("/")}) not found on " +
                    "${bindingClass.name}. The AAR is out of date — rebuild it with " +
                    "android/core-go/build-core.sh or the CI job."
            )
    }

    private fun invoke(name: String, args: List<Any?>): Any? {
        val m = method(name, args.size)
        return try {
            m.invoke(binding, *args.toTypedArray())
        } catch (e: java.lang.reflect.InvocationTargetException) {
            // gomobile methods declare `throws Exception`; surface the cause.
            throw (e.cause ?: e)
        }
    }

    // ---- Mapping Go structs (plain public fields) to Kotlin data classes ----

    private fun field(obj: Any, name: String): Any? = runCatching {
        obj.javaClass.getMethod("get${name.replaceFirstChar { it.uppercase() }}").invoke(obj)
    }.getOrElse {
        obj.javaClass.getField(name).get(obj)
    }

    private fun toDraft(go: Any?): Draft {
        requireNotNull(go) { "GoDraftoEngine: null draft from binding" }
        val tags = runCatching { (field(go, "tags") as? List<*>)?.mapNotNull { it as? String } ?: emptyList() }
            .getOrElse { emptyList() }
        return Draft(
            uuid = field(go, "uuid") as? String ?: "",
            content = field(go, "content") as? String ?: "",
            title = field(go, "title") as? String ?: "",
            tags = tags,
            isFlagged = field(go, "isFlagged") as? Boolean ?: false,
            isArchived = field(go, "isArchived") as? Boolean ?: false,
            isTrashed = field(go, "isTrashed") as? Boolean ?: false,
            folder = field(go, "folder") as? String ?: "inbox",
            createdAt = field(go, "createdAt") as? String ?: "",
            modifiedAt = field(go, "modifiedAt") as? String ?: "",
            permalink = field(go, "permalink") as? String ?: "",
        )
    }

    private fun toCounts(go: Any?): Counts {
        requireNotNull(go) { "GoDraftoEngine: null counts from binding" }
        fun n(name: String) = (field(go, name) as? Number)?.toInt() ?: 0
        return Counts(
            inbox = n("inbox"),
            flagged = n("flagged"),
            archive = n("archive"),
            trash = n("trash"),
            all = n("all"),
        )
    }

    private fun toResult(go: Any?): ActionRunResult {
        requireNotNull(go) { "GoDraftoEngine: null action result from binding" }
        return ActionRunResult(
            uuid = field(go, "uuid") as? String ?: "",
            createdDraft = field(go, "createdDraft") as? Boolean ?: false,
            output = field(go, "output") as? String ?: "",
            copied = field(go, "copied") as? String ?: "",
        )
    }

    private fun stringList(tags: List<String>): Any {
        // gomobile accepts java.util.List for []string parameters.
        return java.util.ArrayList(tags)
    }

    // ---- DraftoEngine ------------------------------------------------------

    override fun createDraft(content: String, tags: List<String>, flagged: Boolean): Draft =
        toDraft(invoke("CreateDraft", listOf(content, stringList(tags), flagged)))

    override fun getDraft(uuid: String): Draft? = runCatching {
        toDraft(invoke("GetDraft", listOf(uuid)))
    }.getOrNull()

    override fun queryDrafts(filter: String, search: String, tags: List<String>, limit: Int): List<Draft> {
        @Suppress("UNCHECKED_CAST")
        val raw = invoke("QueryDrafts", listOf(filter, search, stringList(tags), limit)) as? List<Any?>
        return raw.orEmpty().map { toDraft(it) }
    }

    override fun setFlagged(uuid: String, flagged: Boolean): Draft =
        toDraft(invoke("SetFlagged", listOf(uuid, flagged)))

    override fun archiveDraft(uuid: String) {
        invoke("ArchiveDraft", listOf(uuid))
    }

    override fun trashDraft(uuid: String) {
        invoke("TrashDraft", listOf(uuid))
    }

    override fun replaceDraft(uuid: String, content: String): Draft =
        toDraft(invoke("ReplaceDraft", listOf(uuid, content)))

    override fun addTags(uuid: String, tags: List<String>): Draft =
        toDraft(invoke("AddTags", listOf(uuid, stringList(tags))))

    override fun runAction(actionName: String, uuid: String): ActionRunResult =
        toResult(invoke("RunAction", listOf(actionName, uuid)))

    override fun listTags(): List<String> {
        @Suppress("UNCHECKED_CAST")
        val raw = invoke("ListTags", emptyList()) as? List<Any?> ?: emptyList<Any?>()
        return raw.mapNotNull { it as? String }
    }

    override fun counts(): Counts = toCounts(invoke("Counts", emptyList()))

    override fun registerAction(name: String, stepsJson: String) {
        invoke("RegisterAction", listOf(name, stepsJson))
    }

    /** Releases the underlying Go engine (SQLite handle included). */
    fun close() {
        runCatching { invoke("Close", emptyList()) }
    }

    /** Database file backing this engine. */
    fun databasePath(): String = databasePath

    companion object {
        /** Class generated by `gomobile bind` for the `drafto` package. */
        private const val BINDING_CLASS = "go.drafto.Core"

        /**
         * Returns true when the gomobile binding is on the classpath.
         */
        fun isAvailable(): Boolean = runCatching { Class.forName(BINDING_CLASS) }.isSuccess

        /**
         * Wires the Android context into the Go runtime. Required once, before
         * any other binding call: gomobile's `go.Seq` needs it.
         */
        private fun installContext(context: android.content.Context) {
            runCatching {
                Class.forName("go.Seq")
                    .getMethod("setContext", android.content.Context::class.java)
                    .invoke(null, context)
            }.onFailure {
                android.util.Log.w("GoDraftoEngine", "go.Seq.setContext failed", it)
            }
        }

        /**
         * Opens the persistent engine at [databasePath].
         *
         * Uses the boundary's `NewAt` when exported; falls back to the default
         * constructor when only `New` is available.
         */
        fun openAt(context: android.content.Context, databasePath: String): GoDraftoEngine {
            installContext(context)
            val cls = Class.forName(BINDING_CLASS)
            val instance = runCatching {
                // Package-level function `drafto.NewAt(path)` becomes a static
                // method on the `Core` class generated by gomobile.
                cls.getMethod("NewAt", String::class.java).invoke(null, databasePath)
            }.getOrElse {
                cls.getDeclaredConstructor().newInstance()
                    ?: error("GoDraftoEngine: could not instantiate $BINDING_CLASS")
            }
            return GoDraftoEngine(instance, databasePath)
        }
    }
}
