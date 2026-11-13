package com.drafto.app.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * Reflection adapter over the gomobile-generated AAR.
 *
 * ## Shape of the generated API (verified with javap)
 *
 * ```
 * public abstract class drafto.Drafto {          // package-level functions
 *   public static native drafto.Core new_();     // New()
 *   public static native drafto.Core newAt(java.lang.String) throws Exception;
 * }
 * public final class drafto.Core {               // the bound Go struct
 *   public drafto.Core();
 *   public native void archiveDraft(String) throws Exception;
 *   public native void trashDraft(String) throws Exception;
 *   public native void close() throws Exception;
 *   public native void registerAction(String, String) throws Exception;
 *   ... JSON methods (createDraftJSON, queryDraftsJSON, ...) ...
 * }
 * ```
 *
 * Notes that cost CI cycles to learn:
 *   - The class is **`drafto.Drafto`**, not `go.drafto.Drafto`: `go/` holds only
 *     the runtime (`go.Seq`, `go.Universe`).
 *   - gomobile lowercases the first letter: `NewAt` → `newAt`, `Close` → `close`.
 *   - A method returning a type from another package (`core.Draft`) is dropped
 *     **silently** from the generated class, so the boundary passes JSON.
 *
 * ## Why reflection
 *
 * The AAR is produced by CI (`gomobile bind`) and by `build-core.sh`; it is not
 * in the repository. A compile-time dependency would break every build that
 * does not bind first. Reflection keeps the app compiling everywhere; the real
 * engine activates only when the binding is on the classpath.
 */
class GoDraftoEngine private constructor(
    private val binding: Any,
    private val dbPath: String,
) : DraftoEngine {

    private val bindingClass: Class<*> = binding.javaClass

    // ---- Reflection helpers ------------------------------------------------

    private fun method(name: String, arity: Int): java.lang.reflect.Method =
        bindingClass.methods.firstOrNull { it.name == name && it.parameterCount == arity }
            ?: error(
                "GoDraftoEngine: '$name/$arity' not found on ${bindingClass.name}. " +
                    "The AAR is stale — rerun android/core-go/build-core.sh or the CI job."
            )

    private fun invoke(name: String, vararg args: Any?): Any? {
        val m = method(name, args.size)
        return try {
            m.invoke(binding, *args)
        } catch (e: java.lang.reflect.InvocationTargetException) {
            // gomobile declares `throws Exception`; surface the Go error itself.
            throw (e.cause ?: e)
        }
    }

    /** Binding call returning JSON; "" means "no result". */
    private fun json(name: String, vararg args: Any?): String =
        (invoke(name, *args) as? String) ?: ""

    // ---- JSON → Kotlin models ----------------------------------------------

    private fun toDraft(json: String): Draft {
        val o = JSONObject(json)
        val tags = o.optJSONArray("tags")?.let { arr ->
            (0 until arr.length()).mapNotNull { arr.optString(it) }
        } ?: emptyList()
        return Draft(
            uuid = o.optString("uuid"),
            content = o.optString("content"),
            title = o.optString("title"),
            tags = tags,
            isFlagged = o.optBoolean("isFlagged"),
            isArchived = o.optBoolean("isArchived"),
            isTrashed = o.optBoolean("isTrashed"),
            folder = o.optString("folder", "inbox"),
            createdAt = o.optString("createdAt"),
            modifiedAt = o.optString("modifiedAt"),
            permalink = o.optString("permalink"),
        )
    }

    private fun tagsJson(tags: List<String>): String {
        if (tags.isEmpty()) return ""
        val arr = JSONArray()
        tags.forEach { arr.put(it) }
        return arr.toString()
    }

    // ---- DraftoEngine ------------------------------------------------------

    override fun createDraft(content: String, tags: List<String>, flagged: Boolean): Draft =
        toDraft(json("createDraftJSON", content, tagsJson(tags), flagged))

    override fun getDraft(uuid: String): Draft? =
        json("getDraftJSON", uuid).takeIf { it.isNotEmpty() }?.let { toDraft(it) }

    override fun queryDrafts(filter: String, search: String, tags: List<String>, limit: Int): List<Draft> {
        val raw = json("queryDraftsJSON", filter, search, tagsJson(tags), limit)
        if (raw.isEmpty()) return emptyList()
        val arr = JSONArray(raw)
        return (0 until arr.length()).map { toDraft(arr.getJSONObject(it).toString()) }
    }

    override fun setFlagged(uuid: String, flagged: Boolean): Draft =
        toDraft(json("setFlaggedJSON", uuid, flagged))

    override fun archiveDraft(uuid: String) {
        invoke("archiveDraft", uuid)
    }

    override fun trashDraft(uuid: String) {
        invoke("trashDraft", uuid)
    }

    override fun replaceDraft(uuid: String, content: String): Draft =
        toDraft(json("replaceDraftJSON", uuid, content))

    override fun addTags(uuid: String, tags: List<String>): Draft =
        toDraft(json("addTagsJSON", uuid, tagsJson(tags)))

    override fun runAction(actionName: String, uuid: String): ActionRunResult {
        val o = JSONObject(json("runActionJSON", actionName, uuid))
        return ActionRunResult(
            uuid = o.optString("uuid"),
            createdDraft = o.optBoolean("createdDraft"),
            output = o.optString("output"),
            copied = o.optString("copied"),
        )
    }

    override fun listTags(): List<String> {
        val raw = json("listTagsJSON")
        if (raw.isEmpty()) return emptyList()
        val arr = JSONArray(raw)
        return (0 until arr.length()).map { arr.getString(it) }
    }

    override fun counts(): Counts {
        val raw = json("countsJSON")
        val o = if (raw.isEmpty()) JSONObject() else JSONObject(raw)
        return Counts(
            inbox = o.optInt("inbox"),
            flagged = o.optInt("flagged"),
            archive = o.optInt("archive"),
            trash = o.optInt("trash"),
            all = o.optInt("all"),
        )
    }

    override fun registerAction(name: String, stepsJson: String) {
        invoke("registerAction", name, stepsJson)
    }

    /** Releases the SQLite handle held by the Go engine. */
    fun close() {
        runCatching { invoke("close") }
    }

    fun databasePath(): String = dbPath

    companion object {
        /** Class holding the bound Go struct (`drafto/core-go`). */
        private const val STRUCT_CLASS = "drafto.Core"

        /** Class holding the package-level functions (`New`, `NewAt`). */
        private const val PKG_CLASS = "drafto.Drafto"

        /** True when the gomobile binding is on the classpath. */
        fun isAvailable(): Boolean = runCatching { Class.forName(STRUCT_CLASS) }.isSuccess

        /**
         * Wires the Android context into the Go runtime. gomobile's `go.Seq`
         * needs it before any bound call (files dir, JNI lookups).
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
         * Opens the persistent engine at [dbPath].
         *
         * Prefers `drafto.Drafto.newAt(path)` (SQLite). Falls back to the
         * no-argument constructor (in-memory) so a binding built without
         * `NewAt` degrades to a working — if non-persistent — engine.
         */
        fun openAt(context: android.content.Context, dbPath: String): GoDraftoEngine {
            installContext(context)
            val pkg = runCatching { Class.forName(PKG_CLASS) }.getOrNull()
            val instance: Any? = pkg?.let { cls ->
                runCatching { cls.getMethod("newAt", String::class.java).invoke(null, dbPath) }
                    .onFailure {
                        android.util.Log.w(
                            "GoDraftoEngine",
                            "newAt(\$dbPath) failed; falling back to in-memory new_()", it,
                        )
                    }.getOrNull()
            } ?: Class.forName(STRUCT_CLASS).getDeclaredConstructor().newInstance()
            requireNotNull(instance) { "GoDraftoEngine: could not instantiate $STRUCT_CLASS" }
            return GoDraftoEngine(instance, dbPath)
        }
    }
}
