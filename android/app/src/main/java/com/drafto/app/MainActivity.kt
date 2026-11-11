package com.drafto.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.lifecycle.viewmodel.compose.viewModel
import com.drafto.app.core.DraftoEngine
import com.drafto.app.core.EngineFactory
import com.drafto.app.core.Draft
import com.drafto.app.ui.DraftListScreen
import com.drafto.app.ui.DraftListViewModel
import com.drafto.app.ui.EditorScreen
import com.drafto.app.ui.theme.DraftoTheme

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val engine: DraftoEngine = (application as DraftoApp).engine

        setContent {
            DraftoTheme {
                var editing by remember { mutableStateOf<Draft?>(null) }
                val listVm: DraftListViewModel = viewModel(factory = viewModelFactory {
                    DraftListViewModel(engine)
                })

                val draft = editing
                if (draft != null) {
                    EditorScreen(
                        draft = draft,
                        onBack = { editing = null; listVm.refresh() },
                        onSave = { listVm.save(draft.uuid, it) },
                        onFlag = { listVm.toggleFlag(draft); editing = listVm.selected.value ?: draft },
                        onArchive = { listVm.archive(draft.uuid); editing = null },
                        onTrash = { listVm.trash(draft.uuid); editing = null },
                    )
                } else {
                    DraftListScreen(
                        viewModel = listVm,
                        onOpen = { editing = it },
                    )
                }
            }
        }
    }
}

/** Tiny viewModel factory helper (avoids an extra dependency for the demo). */
private fun <T : androidx.lifecycle.ViewModel> viewModelFactory(
    create: () -> T,
): androidx.lifecycle.ViewModelProvider.Factory =
    object : androidx.lifecycle.ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <VM : androidx.lifecycle.ViewModel> create(modelClass: Class<VM>): VM =
            create() as VM
    }
