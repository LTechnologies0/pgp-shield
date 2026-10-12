package ltechnologies.onionphone.pgpshield.util

import android.content.Context
import java.io.File

/** Deletes leftover share-cache files under `cacheDir/shared`. */
object ShareCacheSweeper {
    fun sweep(context: Context) {
        val dir = File(context.cacheDir, "shared")
        if (!dir.isDirectory) return
        dir.listFiles()?.forEach { file ->
            runCatching { file.delete() }
        }
    }
}
