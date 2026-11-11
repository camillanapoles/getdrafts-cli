package com.drafto.app.core

// ============================================================================
// gomobile binding integration (reference — enable after `gomobile bind`).
//
// Run `android/core-go/build-core.sh` to generate the AAR. It produces a
// Kotlin/Java class (package `go`, class `Core`) with methods matching the
// `//export` functions in `android/core-go/drafto.go`.
//
// The production engine delegates to that class:
//
//   class GoDraftoEngine(private val binding: go.drafto.Core) : DraftoEngine {
//       override fun createDraft(content: String, tags: List<String>, flagged: Boolean): Draft =
//           toDraft(binding.createDraft(content, tags, flagged))
//       override fun getDraft(uuid: String): Draft? =
//           runCatching { toDraft(binding.getDraft(uuid)) }.getOrNull()
//       override fun queryDrafts(filter: String, search: String, tags: List<String>, limit: Int): List<Draft> =
//           binding.queryDrafts(filter, search, tags, limit).map { it.toDraft() }
//       override fun setFlagged(uuid: String, flagged: Boolean): Draft =
//           toDraft(binding.setFlagged(uuid, flagged))
//       override fun archiveDraft(uuid: String) { binding.archiveDraft(uuid) }
//       override fun trashDraft(uuid: String) { binding.trashDraft(uuid) }
//       override fun replaceDraft(uuid: String, content: String): Draft =
//           toDraft(binding.replaceDraft(uuid, content))
//       override fun addTags(uuid: String, tags: List<String>): Draft =
//           toDraft(binding.addTags(uuid, tags))
//       override fun runAction(actionName: String, uuid: String): ActionRunResult {
//           val r = binding.runAction(actionName, uuid)
//           return ActionRunResult(r.uuid, r.createdDraft, r.output, r.copied)
//       }
//       override fun listTags(): List<String> = binding.listTags()
//       override fun counts(): Counts {
//           val c = binding.counts()
//           return Counts(c.inbox, c.flagged, c.archive, c.trash, c.all)
//       }
//       override fun registerAction(name: String, stepsJson: String) {
//           binding.registerAction(name, stepsJson)
//       }
//   }
//
// The generated `go.drafto.Draft`, `go.drafto.Counts`, `go.drafto.ActionRunResult`
// classes expose public fields (uuid, content, title, ...) that the `toDraft`
// adapters map onto the Kotlin data classes above.
// ============================================================================
