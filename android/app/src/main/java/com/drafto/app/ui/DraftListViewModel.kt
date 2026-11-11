package com.drafto.app.ui

import androidx.lifecycle.ViewModel
import com.drafto.app.core.Counts
import com.drafto.app.core.DraftoEngine
import com.drafto.app.core.Draft
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** State holder for the draft list. Thin wrapper over [DraftoEngine]. */
class DraftListViewModel(private val engine: DraftoEngine) : ViewModel() {

    private val _drafts = MutableStateFlow<List<Draft>>(emptyList())
    val drafts: StateFlow<List<Draft>> = _drafts.asStateFlow()

    private val _counts = MutableStateFlow(Counts(0, 0, 0, 0, 0))
    val counts: StateFlow<Counts> = _counts.asStateFlow()

    private val _selected = MutableStateFlow<Draft?>(null)
    val selected: StateFlow<Draft?> = _selected.asStateFlow()

    private val _query = MutableStateFlow("")
    val query: StateFlow<String> = _query.asStateFlow()

    init { refresh() }

    fun refresh() {
        _drafts.value = engine.queryDrafts("inbox", _query.value, emptyList(), 0)
        _counts.value = engine.counts()
    }

    fun setQuery(q: String) {
        _query.value = q
        refresh()
    }

    fun select(d: Draft) { _selected.value = d }
    fun clearSelection() { _selected.value = null }

    fun create(content: String, tags: List<String>, flagged: Boolean) {
        engine.createDraft(content, tags, flagged)
        refresh()
    }

    fun archive(uuid: String) { engine.archiveDraft(uuid); refresh() }
    fun trash(uuid: String) { engine.trashDraft(uuid); refresh() }
    fun toggleFlag(d: Draft) { engine.setFlagged(d.uuid, !d.isFlagged); refresh() }
    fun save(uuid: String, content: String) { engine.replaceDraft(uuid, content); refresh() }
}
