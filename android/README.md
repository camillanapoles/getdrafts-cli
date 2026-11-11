# Drafto Android

App Android do Drafto, built sobre o Go core (`../core`) via **gomobile**.

## Estrutura

```
android/
├── settings.gradle.kts / build.gradle.kts / gradle.properties
├── app/
│   ├── build.gradle.kts
│   └── src/main/
│       ├── AndroidManifest.xml
│       ├── res/                       (themes, strings, colors, icon)
│       └── java/com/drafto/app/
│           ├── DraftoApp.kt          (Application; holds the engine)
│           ├── MainActivity.kt       (list ↔ editor navigation)
│           ├── core/
│           │   ├── DraftoEngine.kt   (interface + mirror data classes)
│           │   ├── FakeEngine.kt     (in-memory Kotlin impl, for preview)
│           │   ├── GoDraftoEngine.kt (gomobile integration reference)
│           │   └── EngineFactory.kt
│           └── ui/
│               ├── DraftListScreen.kt / DraftListViewModel.kt
│               ├── EditorScreen.kt
│               └── theme/
└── core-go/
    ├── drafto.go                      (//export boundary API)
    ├── action.go                      (ParseAction)
    └── build-core.sh                  (gomobile bind → app/libs/drafto.aar)
```

## Como rodar

### Pré-requisitos
- Android Studio (Hedgehog+), JDK 17, Android SDK 34.
- Para o engine nativo: Go 1.21+ e gomobile (`go install golang.org/x/mobile/cmd/gomobile@latest`).

### UI preview (sem gomobile)
O app usa `FakeEngine` por padrão — abre no emulador/preview imediatamente:

```bash
cd android && ./gradlew assembleDebug
# ou abra o projeto no Android Studio e rode ▶
```

### Engine nativo (gomobile)
1. Build the AAR:
   ```bash
   bash android/core-go/build-core.sh
   ```
2. Em `app/build.gradle.kts`, descomente a dependência do AAR:
   ```kotlin
   implementation(fileTree("libs") { include("*.aar") })
   ```
3. Em `EngineFactory`, troque `FakeEngine()` por `GoDraftoEngine(...)` (veja o padrão em `GoDraftoEngine.kt`).
4. Rebuild:
   ```bash
   ./gradlew assembleDebug
   ```

## Navigation & deep links
- Tela inicial: lista do inbox com busca + FAB (novo draft).
- Toque em um draft: editor (flag, archive, trash).
- URL scheme: `drafto://create`, `drafto://open?uuid=...` (manifest).
- Share sheet: recebe `text/plain` de outros apps.

## Phase atual
- Scaffold funcional com UI Compose + FakeEngine.
- Binding Go boundary (`core-go/drafto.go`) pronto para `gomobile bind`.
- Próximo passo (Phase 2): wire gomobile + SQLite backend + actions sheet.
