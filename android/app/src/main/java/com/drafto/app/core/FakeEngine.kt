package com.drafto.app.core

import kotlin.concurrent.synchronized
import kotlin.random.Random

/**
 * In-memory [DraftoEngine] for UI preview and tests. It mirrors the Go
 * `core.MemoryStore` semantics (inbox/archive/trash, flags, tags, query,
 * sorting) so the UI behaves like the production engine before gomobile is
 * wired in.
 */
class FakeEngine : DraftoEngine {

    private val lock = Any()
    private val drafts = mutableMapOf<String, Draft>()
    private val order = mutableListOf<String>()
    private val tagsIndex = mutableSetOf<String>()

    override fun createDraft(content: String, tags: List<String>, flagged: Boolean): Draft {
        return synchronized(lock) {
            val uuid = "d" + Random.nextLong(1, Long.MAX_VALUE).toString(16)
            val now = now()
            val d = Draft(
                uuid = uuid,
                content = content,
                title = titleOf(content),
                tags = tags.toList(),
                isFlagged = flagged,
                folder = "inbox",
                createdAt = now,
                modifiedAt = now,
                permalink = "drafto://open?uuid=$uuid",
            )
            drafts[uuid] = d
            order.add(uuid)
            tags.forEach { tagsIndex.add(it) }
            d
        }
    }

    override fun getDraft(uuid: String): Draft? = synchronized(lock) { drafts[uuid] }

    override fun queryDrafts(
        filter: String,
        search: String,
        tags: List<String>,
        limit: Int,
    ): List<Draft> = synchronized(lock) {
        val q = filter.lowercase()
        order.mapNotNull { drafts[it] }
            .filter { passesFolder(it, q) }
            .filter { search.isBlank() || it.content.contains(search, true) }
            .filter { tags.all { t -> it.tags.contains(t) } }
            .sortedBy { it.createdAt }
            .let { if (limit > 0) it.take(limit) else it }
    }

    override fun setFlagged(uuid: String, flagged: Boolean): Draft = synchronized(lock) {
        mutate(uuid) { copy(isFlagged = flagged) }
    }

    override fun archiveDraft(uuid: String) = synchronized(lock) {
        mutate(uuid) { copy(folder = "archive", isArchived = true, isTrashed = false) }
    }

    override fun trashDraft(uuid: String) = synchronized(lock) {
        mutate(uuid) { copy(folder = "trash", isTrashed = true, isArchived = false) }
    }

    override fun replaceDraft(uuid: String, content: String): Draft = synchronized(lock) {
        mutate(uuid) { copy(content = content, title = titleOf(content)) }
    }

    override fun addTags(uuid: String, tags: List<String>): Draft = synchronized(lock) {
        mutate(uuid) {
            val merged = this.tags + tags
            tagsIndex.addAll(tags)
            copy(tags = merged)
        }
    }

    override fun runAction(actionName: String, uuid: String): ActionRunResult =
        synchronized(lock) {
            val d = drafts[uuid] ?: return ActionRunResult("", false, "", "")
            // Minimal built-in actions for preview.
            val out = when (actionName) {
                "Archive" -> d.copy(folder = "archive", isArchived = true, isTrashed = false)
                "Trash" -> d.copy(folder = "trash", isTrashed = true, isArchived = false)
                "Copy" -> d
                else -> d
            }
            drafts[uuid] = out
            ActionRunResult(uuid, false, out.content, if (actionName == "Copy") out.content else "")
        }

    override fun listTags(): List<String> = synchronized(lock) { tagsIndex.sorted() }

    override fun counts(): Counts = synchronized(lock) {
        var inbox = 0; var flagged = 0; var archive = 0; var trash = 0
        drafts.values.forEach {
            when (it.folder) {
                "inbox" -> { inbox++; if (it.isFlagged) flagged++ }
                "archive" -> archive++
                "trash" -> trash++
            }
        }
        Counts(inbox, flagged, archive, trash, inbox + archive)
    }

    override fun registerAction(name: String, stepsJson: String) {
        // FakeEngine registers a couple of demo actions for the preview.
        if (name == "Archive") Unit
    }

    private inline fun mutate(uuid: String, block: Draft.() -> Draft): Draft = synchronized(lock) {
        val cur = drafts[uuid] ?: return@synchronized Draft(
            "", "", "", emptyList(), false, false, false, "inbox", "", "", ""
        )
        val next = cur.block()
        drafts[uuid] = next
        next
    }

    private fun passesFolder(d: Draft, f: String): Boolean = when (f) {
        "inbox" -> d.folder == "inbox"
        "flagged" -> d.folder == "inbox" && d.isFlagged
        "archive" -> d.folder == "archive"
        "trash" -> d.folder == "trash"
        "all" -> d.folder == "inbox" || d.folder == "archive"
        else -> true
    }

    private fun titleOf(content: String): String =
        content.lineSequence().firstOrNull { it.isNotBlank() }?.trim() ?: ""

    private fun now(): String = java.time.LocalDateTime.now()
        .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))
}
