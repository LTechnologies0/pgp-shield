package ltechnologies.onionphone.pgpshield.engine

/**
 * Bouncy Castle JCA provider registration.
 *
 * Ensures the BC security provider is installed before any cryptographic operation
 * that depends on BC algorithms (DSA, ElGamal, Ed25519, etc.).
 *
 * Lock-free [AtomicInteger] state machine (COLD → WARMING → READY) so concurrent
 * first-calls never double-add and waiters observe a published provider.
 */

import java.security.Security
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.LockSupport
import org.bouncycastle.jce.provider.BouncyCastleProvider

/** Lazily registers the Bouncy Castle JCA provider with atomic single-flight. */
object BouncyCastleProviderHolder {
    /** Registered BC provider name (`BC`). */
    const val PROVIDER: String = BouncyCastleProvider.PROVIDER_NAME

    private const val COLD = 0
    private const val WARMING = 1
    private const val READY = 2

    private val state = AtomicInteger(COLD)

    init {
        ensureRegistered()
    }

    /** Idempotent: installs BC at most once (safe under parallel keygen/encrypt). */
    fun ensureRegistered() {
        when (state.get()) {
            READY -> return
            WARMING -> {
                awaitReady()
                return
            }
        }
        if (!state.compareAndSet(COLD, WARMING)) {
            awaitReady()
            return
        }
        try {
            if (Security.getProvider(PROVIDER) == null) {
                Security.addProvider(BouncyCastleProvider())
            }
            state.set(READY)
        } catch (t: Throwable) {
            state.set(COLD)
            throw t
        }
    }

    private fun awaitReady() {
        var spins = 0
        while (state.get() != READY) {
            if (state.get() == COLD) {
                ensureRegistered()
                return
            }
            if (spins++ < 64) {
                Thread.onSpinWait()
            } else {
                LockSupport.parkNanos(50_000L)
            }
        }
    }
}
