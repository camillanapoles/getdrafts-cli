package com.drafto.app.ui

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Archive
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Flag
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import com.drafto.app.core.Draft

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditorScreen(
    draft: Draft,
    onBack: () -> Unit,
    onSave: (String) -> Unit,
    onFlag: () -> Unit,
    onArchive: () -> Unit,
    onTrash: () -> Unit,
) {
    var text by remember(draft.uuid) { mutableStateOf(draft.content) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(draft.title.ifBlank { "New draft" }) },
                navigationIcon = {
                    IconButton(onClick = { onSave(text); onBack() }) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = onFlag) {
                        Icon(
                            Icons.Default.Flag,
                            contentDescription = "Flag",
                            tint = if (draft.isFlagged) {
                                MaterialTheme.colorScheme.primary
                            } else {
                                MaterialTheme.colorScheme.onSurface
                            },
                        )
                    }
                    IconButton(onClick = onArchive) {
                        Icon(Icons.Default.Archive, contentDescription = "Archive")
                    }
                    IconButton(onClick = onTrash) {
                        Icon(Icons.Default.Delete, contentDescription = "Trash")
                    }
                },
            )
        },
    ) { padding ->
        TextField(
            value = text,
            onValueChange = { text = it },
            modifier = Modifier.fillMaxSize().padding(padding),
        )
    }
}
