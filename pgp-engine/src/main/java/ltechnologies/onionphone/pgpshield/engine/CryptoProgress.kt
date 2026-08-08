package ltechnologies.onionphone.pgpshield.engine

/**
 * Privacy-friendly crypto resource profiler.
 *
 * Tracks **only** operation stage, wall time, and approximate JVM heap delta.
 * Never records plaintext, ciphertext, keys, passphrases, fingerprints, or
 * network/identity data. Snapshots stay in-process (no disk / no telemetry).
 */

import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** High-level crypto operation being profiled. */
enum class CryptoOperation {
    ENCRYPT,
    ENCRYPT_MANY,
    DECRYPT,
    SIGN,
    VERIFY,
    KEYGEN,
    CHANGE_PASSPHRASE,
    ADD_SUBKEY,
    OTHER,
}

/**
 * Coarse Bouncy Castle / engine stages for UI progress.
 *
 * [progress] is a hint in `0f..1f` (not exact work remaining).
 */
enum class CryptoStage(val progress: Float) {
    IDLE(0f),
    PREPARE(0.05f),
    PARSE_KEYS(0.18f),
    GENERATE_KEY_PAIRS(0.30f),
    S2K_PROTECT(0.55f),
    UNLOCK_SECRET(0.40f),
    BUILD_LITERAL(0.55f),
    ENCRYPT_SESSION(0.75f),
    DECRYPT_PAYLOAD(0.70f),
    VERIFY_MDC(0.88f),
    SIGN(0.70f),
    VERIFY_SIGNATURE(0.80f),
    ARMOR(0.92f),
    DONE(1f),
}

/** One completed stage sample (duration only). */
data class CryptoStageSample(
    val stage: CryptoStage,
    val durationMs: Long,
)

/**
 * Local summary after an operation finishes.
 *
 * @property heapDeltaBytes Approximate used-heap change (can be negative after GC).
 */
data class CryptoResourceSummary(
    val operation: CryptoOperation,
    val totalMs: Long,
    val heapDeltaBytes: Long,
    val stages: List<CryptoStageSample>,
)

/** Live snapshot for UI (progress bar + stage label). */
data class CryptoProgressSnapshot(
    val sessionId: Long,
    val operation: CryptoOperation,
    val stage: CryptoStage,
    val progress: Float,
    val elapsedMs: Long,
    val running: Boolean,
    val summary: CryptoResourceSummary? = null,
)

/**
 * Active profiling session. Publish stages via [CryptoProgress.stage]; finish with
 * [CryptoProgress.end].
 */
class CryptoProfileSession internal constructor(
    val id: Long,
    val operation: CryptoOperation,
) {
    internal val startedAtNs: Long = System.nanoTime()
    internal val startHeap: Long = CryptoProgress.usedHeapBytes()
    private val stageStartedAt = AtomicLong(startedAtNs)
    private val currentStage = AtomicReference(CryptoStage.PREPARE)
    internal val samples = ConcurrentLinkedQueue<CryptoStageSample>()

    internal fun markStage(stage: CryptoStage) {
        val now = System.nanoTime()
        val prevStart = stageStartedAt.getAndSet(now)
        val prev = currentStage.getAndSet(stage)
        val ms = ((now - prevStart) / 1_000_000L).coerceAtLeast(0L)
        if (prev != CryptoStage.IDLE && prev != stage) {
            samples.add(CryptoStageSample(prev, ms))
        }
    }

    internal fun finish(): CryptoResourceSummary {
        markStage(CryptoStage.DONE)
        val totalMs = ((System.nanoTime() - startedAtNs) / 1_000_000L).coerceAtLeast(0L)
        val heapDelta = CryptoProgress.usedHeapBytes() - startHeap
        return CryptoResourceSummary(
            operation = operation,
            totalMs = totalMs,
            heapDeltaBytes = heapDelta,
            stages = samples.toList(),
        )
    }
}

/**
 * Process-wide progress bus + profiler entry points.
 *
 * Thread-safe via atomics. Concurrent ops: only the **latest** session publishes
 * to [snapshots] (stale sessions still compute local summaries).
 */
object CryptoProgress {
    private val sessionSeq = AtomicLong(0)
    private val active = AtomicReference<CryptoProfileSession?>(null)
    private val _snapshots = MutableStateFlow<CryptoProgressSnapshot?>(null)
    val snapshots: StateFlow<CryptoProgressSnapshot?> = _snapshots.asStateFlow()

    /** Starts a session and publishes [CryptoStage.PREPARE]. */
    fun begin(operation: CryptoOperation): CryptoProfileSession {
        val session = CryptoProfileSession(sessionSeq.incrementAndGet(), operation)
        active.set(session)
        publish(session, CryptoStage.PREPARE, running = true, summary = null)
        return session
    }

    /** Records a BC/engine stage for the active session (no-op if none). */
    fun stage(stage: CryptoStage) {
        val session = active.get() ?: return
        session.markStage(stage)
        if (active.get()?.id == session.id) {
            publish(session, stage, running = true, summary = null)
        }
    }

    /** Ends [session], publishes DONE + summary, clears active if it still owns the bus. */
    fun end(session: CryptoProfileSession): CryptoResourceSummary {
        val summary = session.finish()
        active.compareAndSet(session, null)
        publish(session, CryptoStage.DONE, running = false, summary = summary)
        return summary
    }

    /** Runs [block] inside a profiled session (sync). */
    inline fun <T> measure(operation: CryptoOperation, block: () -> T): Pair<T, CryptoResourceSummary> {
        val session = begin(operation)
        return try {
            block() to end(session)
        } catch (t: Throwable) {
            end(session)
            throw t
        }
    }

    /** Runs suspending [block] inside a profiled session. */
    suspend inline fun <T> measureSuspend(
        operation: CryptoOperation,
        crossinline block: suspend () -> T,
    ): Pair<T, CryptoResourceSummary> {
        val session = begin(operation)
        return try {
            block() to end(session)
        } catch (t: Throwable) {
            end(session)
            throw t
        }
    }

    internal fun usedHeapBytes(): Long {
        val rt = Runtime.getRuntime()
        return (rt.totalMemory() - rt.freeMemory()).coerceAtLeast(0L)
    }

    private fun publish(
        session: CryptoProfileSession,
        stage: CryptoStage,
        running: Boolean,
        summary: CryptoResourceSummary?,
    ) {
        val elapsed = ((System.nanoTime() - session.startedAtNs) / 1_000_000L).coerceAtLeast(0L)
        _snapshots.value = CryptoProgressSnapshot(
            sessionId = session.id,
            operation = session.operation,
            stage = stage,
            progress = stage.progress,
            elapsedMs = elapsed,
            running = running,
            summary = summary,
        )
    }
}
