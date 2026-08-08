package ltechnologies.onionphone.pgpshield.engine

/**
 * Structured parallel helpers for independent Bouncy Castle / CPU-bound work.
 *
 * Uses coroutine structured concurrency on [Dispatchers.Default] and
 * [java.util.concurrent.atomic] primitives for lock-free coordination
 * (first-success) — no Mutex / synchronized on the hot path.
 */

import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore

/** Lock-free parallel map / race helpers for BC-heavy batches. */
object BcParallel {
    /**
     * Maps [items] in parallel on [Dispatchers.Default], preserving order.
     *
     * @param parallelism Cap on concurrent workers (`null` = one async per item).
     */
    suspend fun <T, R> map(
        items: List<T>,
        parallelism: Int? = null,
        transform: suspend (T) -> R,
    ): List<R> {
        if (items.isEmpty()) return emptyList()
        if (items.size == 1) return listOf(transform(items[0]))
        return coroutineScope {
            if (parallelism == null || parallelism >= items.size) {
                items.map { item ->
                    async(Dispatchers.Default) { transform(item) }
                }.awaitAll()
            } else {
                val limit = Semaphore(parallelism.coerceAtLeast(1))
                items.map { item ->
                    async(Dispatchers.Default) {
                        limit.acquire()
                        try {
                            transform(item)
                        } finally {
                            limit.release()
                        }
                    }
                }.awaitAll()
            }
        }
    }

    /** Indexed parallel map (order-preserving). */
    suspend fun <T, R> mapIndexed(
        items: List<T>,
        parallelism: Int? = null,
        transform: suspend (index: Int, item: T) -> R,
    ): List<R> = map(items.indices.map { it to items[it] }, parallelism) { (i, v) ->
        transform(i, v)
    }

    /**
     * Runs [attempt] for each item in parallel; returns the first non-null result.
     * [AtomicReference.compareAndSet] publishes the winner once (lock-free).
     */
    suspend fun <T, R : Any> firstNotNull(
        items: List<T>,
        attempt: suspend (T) -> R?,
    ): R? {
        if (items.isEmpty()) return null
        if (items.size == 1) return attempt(items[0])
        val winner = AtomicReference<R?>(null)
        coroutineScope {
            items.map { item ->
                async(Dispatchers.Default) {
                    if (winner.get() != null) return@async
                    val value = attempt(item) ?: return@async
                    winner.compareAndSet(null, value)
                }
            }.awaitAll()
        }
        return winner.get()
    }
}
