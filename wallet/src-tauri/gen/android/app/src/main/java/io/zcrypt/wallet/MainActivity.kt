package io.zcrypt.wallet

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import java.io.File
import java.io.InputStream

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    stashOpenedFile(intent)
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    setIntent(intent)
    stashOpenedFile(intent)
  }

  /**
   * A `.zcrypt` file opened with the app (WhatsApp, Files, Gmail, Drive, "Open with"): its
   * text is copied, bounded, into `<dataDir>/inbox`, which the Rust side drains through
   * `take_opened_files` and the Receive screen credits once the wallet is unlocked. Only
   * the copy is kept; the sender's content URI is read once and never stored.
   */
  private fun stashOpenedFile(intent: Intent?) {
    if (intent == null) return
    val uri: Uri = when (intent.action) {
      Intent.ACTION_VIEW -> intent.data
      Intent.ACTION_SEND ->
        if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
        else @Suppress("DEPRECATION") (intent.getParcelableExtra(Intent.EXTRA_STREAM) as? Uri)
      else -> null
    } ?: return
    // Handled once: a configuration change re-delivers the same intent.
    intent.action = null
    try {
      val bytes = contentResolver.openInputStream(uri)?.use { readBounded(it, MAX_BYTES) } ?: return
      if (bytes.isEmpty()) return
      val dir = File(dataDir, "inbox")
      dir.mkdirs()
      File(dir, "${System.currentTimeMillis()}-${bytes.size}.zcrypt").writeBytes(bytes)
    } catch (_: Exception) {
      // Unreadable or oversized: not a payment file. Nothing to do.
    }
  }

  /** The whole stream if it is at most `max` bytes, else empty (a payment file is small). */
  private fun readBounded(s: InputStream, max: Int): ByteArray {
    val buf = ByteArray(max + 1)
    var n = 0
    while (n < buf.size) {
      val r = s.read(buf, n, buf.size - n)
      if (r < 0) break
      n += r
    }
    return if (n > max) ByteArray(0) else buf.copyOf(n)
  }

  companion object {
    private const val MAX_BYTES = 256 * 1024
  }
}
