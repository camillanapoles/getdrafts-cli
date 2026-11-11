# Drafto proguard rules.
# The gomobile binding is a prebuilt AAR; keep its generated classes.
-keep class go.** { *; }
-keep class com.drafto.app.core.Draft { *; }
-keep class com.drafto.app.core.Counts { *; }
-keep class com.drafto.app.core.ActionRunResult { *; }
