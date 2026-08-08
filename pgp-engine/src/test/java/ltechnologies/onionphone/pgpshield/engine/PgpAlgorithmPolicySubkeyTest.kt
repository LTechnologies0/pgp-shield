package ltechnologies.onionphone.pgpshield.engine

import java.time.Instant
import ltechnologies.onionphone.pgpshield.engine.model.KeyRingInfo
import ltechnologies.onionphone.pgpshield.engine.model.SubkeyInfo
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PgpAlgorithmPolicySubkeyTest {

    @Test
    fun defaultSubkey_matchesEd25519Family() {
        assertEquals(
            SubkeyType.ENCRYPT_CV25519,
            PgpAlgorithmPolicy.defaultSubkeyTypeForMaster(PublicKeyAlgorithmTags.Ed25519),
        )
        assertEquals(
            SubkeyType.ENCRYPT_CV25519,
            PgpAlgorithmPolicy.defaultSubkeyTypeForMaster(PublicKeyAlgorithmTags.EDDSA_LEGACY),
        )
    }

    @Test
    fun defaultSubkey_matchesRsaFamily() {
        assertEquals(
            SubkeyType.ENCRYPT_RSA,
            PgpAlgorithmPolicy.defaultSubkeyTypeForMaster(PublicKeyAlgorithmTags.RSA_GENERAL),
        )
    }

    @Test
    fun defaultSubkey_matchesEcdsaFamily() {
        assertEquals(
            SubkeyType.ENCRYPT_ECDH_P256,
            PgpAlgorithmPolicy.defaultSubkeyTypeForMaster(PublicKeyAlgorithmTags.ECDSA),
        )
    }

    @Test
    fun defaultSubkey_forDsaMaster_skipsElGamalInUi() {
        assertEquals(
            SubkeyType.ENCRYPT_RSA,
            PgpAlgorithmPolicy.defaultSubkeyTypeForMaster(PublicKeyAlgorithmTags.DSA),
        )
        assertTrue(
            SubkeyType.ENCRYPT_ELGAMAL !in
                PgpAlgorithmPolicy.preferredSubkeyTypesForMaster(PublicKeyAlgorithmTags.DSA),
        )
    }

    @Test
    fun preferredOrder_putsMatchingFamilyFirst() {
        val preferred = PgpAlgorithmPolicy.preferredSubkeyTypesForMaster(PublicKeyAlgorithmTags.Ed25519)
        assertEquals(SubkeyType.ENCRYPT_CV25519, preferred.first())
        assertTrue(preferred.indexOf(SubkeyType.ENCRYPT_CV25519) < preferred.indexOf(SubkeyType.ENCRYPT_RSA))
        assertTrue(preferred.containsAll(PgpAlgorithmPolicy.androidGeneratableSubkeyTypes))
    }

    @Test
    fun requireAllowedSymmetric_rejectsTripleDes() {
        val ex = assertThrows(PgpException::class.java) {
            PgpAlgorithmPolicy.requireAllowedSymmetric(SymmetricKeyAlgorithmTags.TRIPLE_DES)
        }
        assertEquals(SecurityProblem.INSECURE_ALGORITHM, ex.securityProblem)
    }

    @Test
    fun requireAllowedSymmetric_allowsAes256() {
        PgpAlgorithmPolicy.requireAllowedSymmetric(SymmetricKeyAlgorithmTags.AES_256)
    }

    @Test
    fun validateKeyRing_rejectsWeakRsa() {
        val info = KeyRingInfo(
            masterKeyId = 1L,
            fingerprint = "AA",
            userIds = emptyList(),
            subkeys = listOf(
                SubkeyInfo(
                    keyId = 1L,
                    fingerprint = "AA",
                    algorithm = PublicKeyAlgorithmTags.RSA_GENERAL,
                    creationTime = Instant.now(),
                    expirationTime = null,
                    isRevoked = false,
                    flags = 0,
                    bitStrength = 1024,
                ),
            ),
            isSecret = false,
            isRevoked = false,
        )
        val ex = assertThrows(PgpException::class.java) {
            PgpAlgorithmPolicy.validateKeyRing(info)
        }
        assertEquals(SecurityProblem.INSECURE_ALGORITHM, ex.securityProblem)
        assertTrue(ex.message!!.contains("1024"))
    }

    @Test
    fun requireAllowedHash_rejectsSha1() {
        val ex = assertThrows(PgpException::class.java) {
            PgpAlgorithmPolicy.requireAllowedHash(org.bouncycastle.bcpg.HashAlgorithmTags.SHA1)
        }
        assertEquals(SecurityProblem.INSECURE_ALGORITHM, ex.securityProblem)
    }

    @Test
    fun requireAllowedCompression_rejectsUnknown() {
        val ex = assertThrows(PgpException::class.java) {
            PgpAlgorithmPolicy.requireAllowedCompression(99)
        }
        assertEquals(SecurityProblem.INSECURE_ALGORITHM, ex.securityProblem)
    }

    @Test
    fun validateKeyRing_rejectsWeakDsa() {
        val info = KeyRingInfo(
            masterKeyId = 1L,
            fingerprint = "AA",
            userIds = emptyList(),
            subkeys = listOf(
                SubkeyInfo(
                    keyId = 1L,
                    fingerprint = "AA",
                    algorithm = PublicKeyAlgorithmTags.DSA,
                    creationTime = Instant.now(),
                    expirationTime = null,
                    isRevoked = false,
                    flags = 0,
                    bitStrength = 1024,
                ),
            ),
            isSecret = false,
            isRevoked = false,
        )
        val ex = assertThrows(PgpException::class.java) {
            PgpAlgorithmPolicy.validateKeyRing(info)
        }
        assertEquals(SecurityProblem.INSECURE_ALGORITHM, ex.securityProblem)
        assertTrue(ex.message!!.contains("DSA"))
    }

    @Test
    fun validateKeyRing_rejectsUnknownRsaStrength() {
        val info = KeyRingInfo(
            masterKeyId = 1L,
            fingerprint = "AA",
            userIds = emptyList(),
            subkeys = listOf(
                SubkeyInfo(
                    keyId = 1L,
                    fingerprint = "AA",
                    algorithm = PublicKeyAlgorithmTags.RSA_GENERAL,
                    creationTime = Instant.now(),
                    expirationTime = null,
                    isRevoked = false,
                    flags = 0,
                    bitStrength = 0,
                ),
            ),
            isSecret = false,
            isRevoked = false,
        )
        assertThrows(PgpException::class.java) {
            PgpAlgorithmPolicy.validateKeyRing(info)
        }
    }

    @Test
    fun validateKeyRing_rejectsDisallowedPublicKeyAlg() {
        val info = KeyRingInfo(
            masterKeyId = 1L,
            fingerprint = "AA",
            userIds = emptyList(),
            subkeys = listOf(
                SubkeyInfo(
                    keyId = 1L,
                    fingerprint = "AA",
                    algorithm = PublicKeyAlgorithmTags.DIFFIE_HELLMAN,
                    creationTime = Instant.now(),
                    expirationTime = null,
                    isRevoked = false,
                    flags = 0,
                    bitStrength = 2048,
                ),
            ),
            isSecret = false,
            isRevoked = false,
        )
        assertThrows(PgpException::class.java) {
            PgpAlgorithmPolicy.validateKeyRing(info)
        }
    }

    @Test
    fun validateKeyRing_rejectsUnknownEccCurve() {
        val info = KeyRingInfo(
            masterKeyId = 1L,
            fingerprint = "AA",
            userIds = emptyList(),
            subkeys = listOf(
                SubkeyInfo(
                    keyId = 1L,
                    fingerprint = "AA",
                    algorithm = PublicKeyAlgorithmTags.ECDSA,
                    creationTime = Instant.now(),
                    expirationTime = null,
                    isRevoked = false,
                    flags = 0,
                    bitStrength = 256,
                    curveOid = "1.3.132.0.10", // secp256k1
                ),
            ),
            isSecret = false,
            isRevoked = false,
        )
        val ex = assertThrows(PgpException::class.java) {
            PgpAlgorithmPolicy.validateKeyRing(info)
        }
        assertTrue(ex.message!!.contains("curve", ignoreCase = true))
    }

    @Test
    fun requireHashStrengthForKey_rejectsSha256OnP521SizedKey() {
        // Simulate P-521 ECDSA: signatureHashForPublicKey would require SHA-512.
        // We cannot easily build a PGPPublicKey here without BC; exercise digest-bit helper
        // via policy thresholds using a generated ECDSA P-521 key when available.
        BouncyCastleProviderHolder.ensureRegistered()
        val pass = "p521-hash".toCharArray()
        val key = try {
            KeyGenerator().generateKeyRingBlocking(
                GenerateKeyRequest(
                    userId = "P521 <p@e.com>",
                    passphrase = pass,
                    algorithmType = KeyAlgorithmType.ECDSA_P521,
                ),
            )
        } catch (_: Exception) {
            // Skip if generator unavailable on this JVM.
            return
        } finally {
            pass.fill('\u0000')
        }
        val ring = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(key.publicArmored.inputStream()).use { input ->
            org.bouncycastle.openpgp.PGPObjectFactory(
                input,
                org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator(),
            ).nextObject() as org.bouncycastle.openpgp.PGPPublicKeyRing
        }
        val master = ring.publicKey
        if (master.bitStrength < 512) return
        assertThrows(PgpException::class.java) {
            PgpAlgorithmPolicy.requireHashStrengthForKey(
                master,
                org.bouncycastle.bcpg.HashAlgorithmTags.SHA256,
            )
        }
        PgpAlgorithmPolicy.requireHashStrengthForKey(
            master,
            org.bouncycastle.bcpg.HashAlgorithmTags.SHA512,
        )
    }
}
