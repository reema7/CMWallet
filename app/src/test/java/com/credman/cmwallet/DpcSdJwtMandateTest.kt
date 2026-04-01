package com.credman.cmwallet

import com.credman.cmwallet.openid4vp.DelegateProposal
import com.credman.cmwallet.openid4vp.OpenId4VP
import com.credman.cmwallet.sdjwt.SdJwt
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64 as JBase64

/**
 * dSD-JWT HITL mandate tests for [SdJwt.presentWithDelegations].
 *
 * The scenario: a DPC SD-JWT credential is presented in response to an OID4VP request that
 * carries two mandate proposals via `transaction_data[].type = "delegate"`:
 *   1. checkout mandate  (vct = "mandate.checkout.1", checkout_hash)
 *   2. payment mandate   (vct = "mandate.payment",    open with constraints)
 *
 * Wallet produces a dSD-JWT chain:
 *   dpc_issuer_jwt ~ dpc_discs ~ checkout_discs ~ KB-SD-JWT_checkout
 *                  ~ payment_discs ~ KB-SD-JWT_payment ~
 *
 * All KB-SD-JWTs signed by the holder's device key.
 * The agent appends its own KB-JWT (with its key from cnf.jwk) when presenting to a verifier.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, sdk = [33])
class DpcSdJwtMandateTest {

    // Holder (device) private key PKCS8 – from databasenew.json dpc_v3_2_sdjwt
    private val holderPrivKeyB64Url =
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgD17D2RSlvQ8ElFrP" +
        "qEG3JfXTjxyKEH9DMpFnWp_Z63ihRANCAATyMFauK4kFj767__aM4l9xfgmPiQSp" +
        "jgJRf1x_VtB11nLB9pDhoZXpoUUbj1GBSiWGYFahF0IdiX6LUShkTHyx"

    private lateinit var dpcCredential: String
    private lateinit var holderKeyNormalized: String
    private lateinit var agentPubKeyJwk: JSONObject

    private val TEST_NONCE = "test-nonce-abc123"
    private val TEST_AUD   = "origin:https://pay.example.com"
    private val DPC_CRED_ID = "dpc_credential"

    @Before
    fun setUp() {
        dpcCredential = DPC_SDJWT_CREDENTIAL

        // Normalise holder key to base64url-no-padding
        holderKeyNormalized = holderPrivKeyB64Url
            .replace("+", "-").replace("/", "_").replace("=", "")
            .replace("\n", "").replace(" ", "")

        // Generate agent key pair
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val agentKp = kpg.generateKeyPair()
        val agentPub = agentKp.public as ECPublicKey
        agentPubKeyJwk = JSONObject().apply {
            put("kty", "EC"); put("crv", "P-256"); put("use", "sig")
            put("x", encodeCoord(agentPub.w.affineX.toByteArray()))
            put("y", encodeCoord(agentPub.w.affineY.toByteArray()))
        }
    }

    private fun encodeCoord(raw: ByteArray): String {
        val fixed = if (raw.size > 32) raw.copyOfRange(raw.size - 32, raw.size)
                    else raw.copyOf(32).also { raw.copyInto(it, 32 - raw.size) }
        return JBase64.getUrlEncoder().withoutPadding().encodeToString(fixed)
    }

    // ── Fixture builders ───────────────────────────────────────────────────────

    private fun checkoutPayload(checkoutHash: String = "oK0usjWjRUaXbH2PHBvhRGfldH4") =
        JSONObject().apply {
            put("vct", "mandate.checkout.1")
            put("exp", 9_999_999_999L)
            put("cnf", JSONObject().put("jwk", agentPubKeyJwk))
            put("checkout_hash", checkoutHash)
        }

    private fun paymentPayload() = JSONObject().apply {
        put("vct", "mandate.payment")
        put("exp", 9_999_999_999L)
        put("cnf", JSONObject().put("jwk", agentPubKeyJwk))
        put("constraints", JSONArray().apply {
            put(JSONObject().apply {
                put("type", "payment.amount"); put("currency", "USD"); put("max", "150.00")
            })
            put(JSONObject().apply {
                put("type", "payment.allowed_payees")
                put("allowed", JSONArray().put("rideshare.example"))
            })
        })
    }

    private fun encodeDelegateItem(
        delegatePayloads: List<JSONObject>,
        delegateDisclosures: List<String> = emptyList()
    ): String {
        val item = JSONObject().apply {
            put("type", "delegate")
            put("format", "dc+sd-jwt")
            put("credential_ids", JSONArray().put(DPC_CRED_ID))
            put("delegate_payload", JSONArray().apply { delegatePayloads.forEach { put(it) } })
            put("delegate_disclosures", JSONArray().apply { delegateDisclosures.forEach { put(it) } })
        }
        return JBase64.getUrlEncoder().withoutPadding()
            .encodeToString(item.toString().toByteArray())
    }

    // Convenience overload for single payload (backward compat in tests)
    private fun encodeDelegateItem(
        delegatePayload: JSONObject,
        delegateDisclosures: List<String> = emptyList()
    ) = encodeDelegateItem(listOf(delegatePayload), delegateDisclosures)

    private fun oid4vpRequest(txItems: List<String> = emptyList()) = JSONObject().apply {
        put("nonce", TEST_NONCE)
        put("client_id", TEST_AUD)
        put("dcql_query", JSONObject().apply {
            put("credentials", JSONArray().put(JSONObject().apply {
                put("id", DPC_CRED_ID)
                put("format", "dc+sd-jwt")
                put("meta", JSONObject().put("vct_values", JSONArray().put("com.emvco.dpc")))
                put("claims", JSONArray().apply {
                    put(JSONObject().put("path", JSONArray().put("card_last_four")))
                    put(JSONObject().put("path", JSONArray().put("credential_id")))
                })
            }))
        })
        if (txItems.isNotEmpty()) put("transaction_data", JSONArray().apply { txItems.forEach { put(it) } })
    }

    private fun decodeJwt(compact: String): Pair<JSONObject, JSONObject> {
        fun dec(b64: String): JSONObject {
            val p = b64.padEnd(b64.length + (4 - b64.length % 4) % 4, '=')
            return JSONObject(String(JBase64.getUrlDecoder().decode(p)))
        }
        val parts = compact.split(".")
        return dec(parts[0]) to dec(parts[1])
    }

    private fun sha256b64url(input: String): String =
        JBase64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(input.toByteArray()))

    // ── Tests ──────────────────────────────────────────────────────────────────

    @Test
    fun `OpenId4VP correctly parses two delegate proposals`() {
        // Both mandate payloads in ONE transaction_data item, inside delegate_payload[]
        val item = encodeDelegateItem(listOf(checkoutPayload(), paymentPayload()))
        val oid4vp = OpenId4VP(oid4vpRequest(listOf(item)), TEST_AUD, "openid4vp-v1-qrcode")

        assertEquals(2, oid4vp.delegateProposals.size)
        with(oid4vp.delegateProposals[0]) {
            assertEquals("dc+sd-jwt", format)
            assertEquals("mandate.checkout.1", delegatePayload.getString("vct"))
            assertTrue(delegatePayload.has("checkout_hash"))
            assertTrue(delegatePayload.has("cnf"))
        }
        with(oid4vp.delegateProposals[1]) {
            assertEquals("mandate.payment", delegatePayload.getString("vct"))
            assertEquals(2, delegatePayload.getJSONArray("constraints").length())
        }
    }

    @Test
    fun `delegate_disclosures are matched to payload by digest not position`() {
        // Build a real disclosure and put its digest in the checkout payload _sd
        val disclosureArr = JSONArray().put("test-salt").put("checkout_jwt").put("eyJpZCI6InRlc3QifQ")
        val disclosureB64 = JBase64.getUrlEncoder().withoutPadding()
            .encodeToString(disclosureArr.toString().toByteArray())
        val discDigest = JBase64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(disclosureB64.toByteArray()))

        // Checkout payload references the digest in _sd; payment payload does not
        val checkout = checkoutPayload().apply { put("_sd", JSONArray().put(discDigest)) }
        val payment  = paymentPayload()  // no _sd

        // Single transaction_data item with both payloads and the disclosure
        val item = encodeDelegateItem(listOf(checkout, payment), listOf(disclosureB64))
        val oid4vp = OpenId4VP(oid4vpRequest(listOf(item)), TEST_AUD, "openid4vp-v1-qrcode")

        assertEquals(2, oid4vp.delegateProposals.size)
        // Checkout proposal gets the disclosure (digest matched)
        assertEquals(1, oid4vp.delegateProposals[0].delegateDisclosures.size)
        assertEquals(disclosureB64, oid4vp.delegateProposals[0].delegateDisclosures[0])
        // Payment proposal gets nothing (no matching digest)
        assertEquals(0, oid4vp.delegateProposals[1].delegateDisclosures.size)
    }

    @Test
    fun `no delegate proposals means empty list`() {
        val oid4vp = OpenId4VP(oid4vpRequest(), TEST_AUD, "openid4vp-v1-qrcode")
        assertTrue(oid4vp.delegateProposals.isEmpty())
    }

    @Test
    fun `presentWithDelegations chain ends with trailing tilde and no KB-JWT`() {
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload(), emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(),  emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKeyNormalized).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        // trailing ~ signals "no agent KB-JWT yet"
        assertTrue("Chain must end with ~", chain.endsWith("~"))
        // The last non-empty part is the second KB-SD-JWT (a compact JWT)
        val parts = chain.split("~").filter { it.isNotEmpty() }
        assertEquals("Last part must be compact JWT (KB-SD-JWT_payment)",
            3, parts.last().split(".").size)
    }

    @Test
    fun `KB-SD-JWT_checkout has correct mandate payload claims`() {
        val hash = "SomeCheckoutHash123"
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload(hash), emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKeyNormalized).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        val parts = chain.split("~").filter { it.isNotEmpty() }
        val kbSdJwt = parts.last()
        val (header, payload) = decodeJwt(kbSdJwt)

        // Header
        assertEquals("kb+jwt", header.getString("typ"))
        assertEquals("ES256",  header.getString("alg"))

        // Standard KB fields
        assertEquals(TEST_NONCE, payload.getString("nonce"))
        assertEquals(TEST_AUD,   payload.getString("aud"))
        assertTrue("sd_hash must be present", payload.has("sd_hash"))
        assertTrue("iat must be present",     payload.has("iat"))

        // Mandate fields from delegate_payload
        assertEquals("mandate.checkout.1", payload.getString("vct"))
        assertEquals(hash, payload.getString("checkout_hash"))
        assertTrue("cnf.jwk must be present", payload.getJSONObject("cnf").has("jwk"))
        // cnf.jwk should equal the agent's public key
        val kbJwk = payload.getJSONObject("cnf").getJSONObject("jwk")
        assertEquals(agentPubKeyJwk.getString("x"), kbJwk.getString("x"))
        assertEquals(agentPubKeyJwk.getString("y"), kbJwk.getString("y"))
    }

    @Test
    fun `KB-SD-JWT_payment has correct constraint fields`() {
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", paymentPayload(), emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKeyNormalized).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        val parts = chain.split("~").filter { it.isNotEmpty() }
        val (_, payload) = decodeJwt(parts.last())

        assertEquals("mandate.payment", payload.getString("vct"))
        val constraints = payload.getJSONArray("constraints")
        assertEquals(2, constraints.length())

        val amtConstraint = constraints.getJSONObject(0)
        assertEquals("payment.amount", amtConstraint.getString("type"))
        assertEquals("USD", amtConstraint.getString("currency"))
        assertEquals("150.00", amtConstraint.getString("max"))

        val payeeConstraint = constraints.getJSONObject(1)
        assertEquals("payment.allowed_payees", payeeConstraint.getString("type"))
        assertEquals("rideshare.example",
            payeeConstraint.getJSONArray("allowed").getString(0))
    }

    @Test
    fun `sd_hash in each KB-SD-JWT covers only DPC base — parallel design`() {
        // Parallel design: both KB-SD-JWTs root independently in the DPC.
        // sd_hash = SHA-256(dpc_jwt ~ dpc_discs ~ [mandate_own_discs] ~)
        // KB-SD-JWT_payment does NOT include KB-SD-JWT_checkout in its sd_hash.
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload(), emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(),  emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKeyNormalized).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        val parts = chain.split("~").dropLast(1)
        val kbPositions = parts.indices.filter { it > 0 && parts[it].split(".").size == 3 }
        assertEquals(2, kbPositions.size)

        val pos1 = kbPositions[0]
        val pos2 = kbPositions[1]

        // DPC base parts = everything before the first KB-SD-JWT (issuer_jwt + dpc_discs)
        val dpcBase = parts.subList(0, pos1).joinToString("~", postfix = "~")
        val expectedDpcHash = sha256b64url(dpcBase)

        val (_, p1) = decodeJwt(parts[pos1])
        val (_, p2) = decodeJwt(parts[pos2])

        // Both mandates have the same sd_hash base (DPC only, no delegate discs in either)
        assertEquals("KB-SD-JWT_checkout sd_hash must cover DPC base only", expectedDpcHash, p1.getString("sd_hash"))
        assertEquals("KB-SD-JWT_payment sd_hash must cover DPC base only", expectedDpcHash, p2.getString("sd_hash"))

        // They are equal because neither proposal has delegate_disclosures
        assertEquals("Both sd_hashes equal in this case (no delegate discs)", p1.getString("sd_hash"), p2.getString("sd_hash"))
    }

    @Test
    fun `transaction_data_hashes in last KB-SD-JWT only`() {
        val txHash = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload(), emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(),  emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKeyNormalized).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD,
            mapOf(DPC_CRED_ID to listOf(txHash)),
            proposals
        )
        val parts = chain.split("~").filter { it.isNotEmpty() }
        val kbJwts = parts.drop(1).filter { it.split(".").size == 3 }
        assertEquals(2, kbJwts.size)

        val (_, p1) = decodeJwt(kbJwts[0])
        val (_, p2) = decodeJwt(kbJwts[1])

        assertFalse("First KB-SD-JWT must NOT contain tx_data hash", p1.has(DPC_CRED_ID))
        assertTrue("Last KB-SD-JWT must contain tx_data hash",       p2.has(DPC_CRED_ID))
    }

    @Test
    fun `delegate_disclosures appear in chain before their KB-SD-JWT`() {
        val checkoutJwtValue = "eyJhbGciOiJFUzI1NiJ9.eyJpZCI6Im9yZGVyXzEyMyJ9.sig"
        val disclosureArr = JSONArray().put("test_salt").put("checkout_jwt").put(checkoutJwtValue)
        val disclosureB64 = JBase64.getUrlEncoder().withoutPadding()
            .encodeToString(disclosureArr.toString().toByteArray())
        val digest = sha256b64url(disclosureB64)

        val payload = checkoutPayload().apply {
            remove("checkout_hash")
            put("_sd", JSONArray().put(digest))
            put("_sd_alg", "sha-256")
        }
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", payload, listOf(disclosureB64), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKeyNormalized).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        val parts = chain.split("~").dropLast(1)
        val discPos = parts.indexOf(disclosureB64)
        val kbPos   = parts.indexOfFirst { it.split(".").size == 3 && parts.indexOf(it) > 0 }

        assertTrue("Disclosure must appear in chain (pos=$discPos)", discPos >= 0)
        assertTrue("Disclosure must be BEFORE its KB-SD-JWT (disc=$discPos, kb=$kbPos)", discPos < kbPos)
    }

    @Test
    fun `full chain with both mandates matches expected dSD-JWT structure`() {
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload(), emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(),  emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKeyNormalized).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )

        // Split and categorise
        val parts = chain.split("~").dropLast(1)
        val compactParts = parts.filter { it.split(".").size == 3 }
        val disclosures  = parts.filter { it.split(".").size != 3 }

        // First compact part is the DPC issuer JWT
        val issuerJwt = compactParts[0]
        val (issuerHdr, _) = decodeJwt(issuerJwt)
        assertEquals("dc+sd-jwt", issuerHdr.getString("typ"))

        // Remaining compact parts are the KB-SD-JWTs (2 of them)
        val kbSdJwts = compactParts.drop(1)
        assertEquals(2, kbSdJwts.size)

        // All non-compact parts (excluding issuer JWT position) are disclosures
        // (DPC disclosures come from the credential itself)
        assertTrue("Must have DPC disclosures", disclosures.isNotEmpty())

        // vct values in the two KB-SD-JWTs
        val vcts = kbSdJwts.map { decodeJwt(it).second.getString("vct") }
        assertTrue(vcts.contains("mandate.checkout.1"))
        assertTrue(vcts.contains("mandate.payment"))

        println("✓ dSD-JWT chain structure:")
        println("  DPC issuer JWT: ${issuerJwt.take(40)}...")
        println("  DPC disclosures: ${disclosures.size}")
        println("  KB-SD-JWT_1 (${vcts[0]}): ${kbSdJwts[0].take(40)}...")
        println("  KB-SD-JWT_2 (${vcts[1]}): ${kbSdJwts[1].take(40)}...")
    }  // end test

    // ── Incremental presentability tests ──────────────────────────────────────
    //
    // The chain structure:
    //   dpc_jwt ~ dpc_discs ~ KB-SD-JWT_checkout ~ KB-SD-JWT_payment ~
    //
    // enables TWO independent presentations (agent appends its own KB-JWT to a prefix):
    //
    //   Prefix 1 (to merchant/checkout verifier):
    //     dpc_jwt ~ dpc_discs ~ KB-SD-JWT_checkout ~ [agent_kb_jwt]
    //
    //   Prefix 2 (to payment network — carries full consent chain):
    //     dpc_jwt ~ dpc_discs ~ KB-SD-JWT_checkout ~ KB-SD-JWT_payment ~ [agent_kb_jwt]
    //
    // The agent_kb_jwt in each case has sd_hash covering the chain up to (not including) itself.
    // KB-SD-JWT_checkout's sd_hash proves it was signed over just the DPC.
    // KB-SD-JWT_payment's sd_hash proves it was signed over DPC + checkout mandate — linking them.

    /**
     * Simulates the agent appending a KB-JWT to a chain prefix.
     * In production the agent signs with its private key; here we use the holder key as a stand-in.
     */
    private fun agentAddKbJwt(chainPrefix: String, agentNonce: String, agentAud: String): String {
        require(chainPrefix.endsWith("~")) { "Chain prefix must end with ~" }
        val sdHash = sha256b64url(chainPrefix)
        val header = """{"typ":"kb+jwt","alg":"ES256"}"""
        val payload = """{"iat":${System.currentTimeMillis()/1000},"aud":"$agentAud","nonce":"$agentNonce","sd_hash":"$sdHash"}"""
        // In tests we use the holder key as a proxy for the agent key (both are EC P-256)
        val holderKey = java.security.KeyFactory.getInstance("EC")
            .generatePrivate(java.security.spec.PKCS8EncodedKeySpec(
                JBase64.getUrlDecoder().decode(holderKeyNormalized.padEnd(
                    holderKeyNormalized.length + (4 - holderKeyNormalized.length % 4) % 4, '='
                ))
            ))
        val h64 = JBase64.getUrlEncoder().withoutPadding().encodeToString(header.toByteArray())
        val p64 = JBase64.getUrlEncoder().withoutPadding().encodeToString(payload.toByteArray())
        val sig = java.security.Signature.getInstance("SHA256withECDSA").apply {
            initSign(holderKey)
            update("$h64.$p64".toByteArray())
        }.sign()
        // Convert DER signature to raw R||S (JWS format)
        val r = sig.copyOfRange(4, 4 + sig[3].toInt())
        val s = sig.copyOfRange(4 + sig[3].toInt() + 2, sig.size)
        val rawR = if (r.size > 32) r.copyOfRange(r.size - 32, r.size) else r.copyOf(32).also { r.copyInto(it, 32 - r.size) }
        val rawS = if (s.size > 32) s.copyOfRange(s.size - 32, s.size) else s.copyOf(32).also { s.copyInto(it, 32 - s.size) }
        val rawSig = JBase64.getUrlEncoder().withoutPadding().encodeToString(rawR + rawS)
        return chainPrefix + "$h64.$p64.$rawSig"
    }

    @Test
    fun `checkout mandate is independently presentable to merchant`() {
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload(), emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(),  emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKeyNormalized).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        val parts = chain.split("~").dropLast(1)

        // Checkout KB-SD-JWT is at the first compact-JWT position after the issuer JWT
        val kbPos = parts.indices.first { it > 0 && parts[it].split(".").size == 3 }
        val checkoutKbSdJwt = parts[kbPos]

        // Agent builds: dpc_jwt ~ dpc_discs ~ KB-SD-JWT_checkout ~
        val checkoutPrefix = parts.subList(0, kbPos + 1).joinToString("~", postfix = "~")

        // Agent appends its KB-JWT for presentation to a merchant
        val merchantNonce = "merchant-nonce-xyz"
        val merchantAud   = "origin:https://merchant.example"
        val presentedToMerchant = agentAddKbJwt(checkoutPrefix, merchantNonce, merchantAud)

        // Verify structure: ends with a compact JWT (agent KB-JWT)
        assertFalse("Full chain must not end with ~", presentedToMerchant.endsWith("~"))
        val pParts = presentedToMerchant.split("~").filter { it.isNotEmpty() }
        assertEquals("Agent KB-JWT must be 3-part compact JWT", 3, pParts.last().split(".").size)

        // Verify agent KB-JWT's sd_hash covers exactly the checkout prefix
        val (_, agentKbPayload) = decodeJwt(pParts.last())
        val expectedSdHash = sha256b64url(checkoutPrefix)
        assertEquals("sd_hash in agent KB-JWT must cover checkout prefix", expectedSdHash, agentKbPayload.getString("sd_hash"))
        assertEquals(merchantNonce, agentKbPayload.getString("nonce"))
        assertEquals(merchantAud,   agentKbPayload.getString("aud"))

        // The KB-SD-JWT_checkout payload is still intact with mandate content
        val (_, checkoutPayloadJson) = decodeJwt(checkoutKbSdJwt)
        assertEquals("mandate.checkout.1", checkoutPayloadJson.getString("vct"))

        println("✓ Checkout-only presentation to merchant:")
        println("  Chain parts: ${pParts.size}  (issuer_jwt + ${pParts.size - 3} dpc_discs + KB-SD-JWT_checkout + agent_kb_jwt)")
    }

    @Test
    fun `payment mandate presentation to payment network uses DPC prefix only — no checkout KB-SD-JWT`() {
        // Parallel design: payment network only gets DPC + KB-SD-JWT_payment.
        // They never see the checkout mandate or checkout_jwt disclosure.
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload(), emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(),  emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKeyNormalized).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        val parts = chain.split("~").dropLast(1)
        val kbPositions = parts.indices.filter { it > 0 && parts[it].split(".").size == 3 }
        assertEquals(2, kbPositions.size)

        val pos1 = kbPositions[0]  // KB-SD-JWT_checkout position
        val pos2 = kbPositions[1]  // KB-SD-JWT_payment position

        // Agent builds payment-only prefix: dpc_jwt ~ dpc_discs ~ KB-SD-JWT_payment ~
        // Skip checkout disc and KB-SD-JWT_checkout — payment network should not see them
        val dpcParts = parts.subList(0, pos1)  // issuer_jwt + dpc_discs (before checkout KB-SD-JWT)
        val paymentKbSdJwt = parts[pos2]
        val paymentPrefix = (dpcParts + listOf(paymentKbSdJwt)).joinToString("~", postfix = "~")

        val paymentNonce = "payment-network-nonce-abc"
        val paymentAud   = "origin:https://paymentnetwork.example"
        val presentedToNetwork = agentAddKbJwt(paymentPrefix, paymentNonce, paymentAud)

        assertFalse("Must not end with ~", presentedToNetwork.endsWith("~"))
        val pParts = presentedToNetwork.split("~").filter { it.isNotEmpty() }

        // Agent KB-JWT sd_hash covers only dpc_base + KB-SD-JWT_payment
        val (_, agentKbPayload) = decodeJwt(pParts.last())
        val expectedSdHash = sha256b64url(paymentPrefix)
        assertEquals("sd_hash must cover payment prefix only", expectedSdHash, agentKbPayload.getString("sd_hash"))
        assertEquals(paymentNonce, agentKbPayload.getString("nonce"))
        assertEquals(paymentAud,   agentKbPayload.getString("aud"))

        // Only one KB-SD-JWT in the presented chain (payment only, no checkout)
        val kbSdJwts = pParts.drop(1).dropLast(1).filter { it.split(".").size == 3 }
        assertEquals("Payment-only chain must carry only the payment KB-SD-JWT", 1, kbSdJwts.size)
        assertEquals("mandate.payment", decodeJwt(kbSdJwts[0]).second.getString("vct"))

        println("✓ Payment-only presentation to credential provider:")
        println("  Chain parts: ${pParts.size}  (issuer_jwt + dpc_discs + KB-SD-JWT_payment + agent_kb_jwt)")
        println("  Checkout KB-SD-JWT NOT included — payment network never sees cart details")
    }

    @Test
    fun `payment mandate sd_hash covers only DPC base — parallel design`() {
        // Parallel design: KB-SD-JWT_payment.sd_hash = SHA-256(dpc_jwt~dpc_discs~)
        // It does NOT include KB-SD-JWT_checkout.
        // Cross-mandate binding is via constraints.payment.reference.checkout_reference (application layer).
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload("specific-checkout-hash"), emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(), emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKeyNormalized).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        val parts = chain.split("~").dropLast(1)
        val kbPositions = parts.indices.filter { it > 0 && parts[it].split(".").size == 3 }
        assertEquals(2, kbPositions.size)

        val pos1 = kbPositions[0]  // KB-SD-JWT_checkout
        val pos2 = kbPositions[1]  // KB-SD-JWT_payment

        val (_, p2) = decodeJwt(parts[pos2])
        val actualSdHash2 = p2.getString("sd_hash")

        // sd_hash in payment mandate = SHA-256(dpc_jwt~dpc_discs~) only
        // dpc_discs are parts[1..pos1-1] (everything before checkout KB-SD-JWT and its discs)
        val dpcOnlyParts = parts.subList(0, pos1)  // issuer_jwt + dpc_discs (no checkout content)
        val expectedSdHash2 = sha256b64url(dpcOnlyParts.joinToString("~", postfix = "~"))
        assertEquals("Payment sd_hash must cover DPC base only", expectedSdHash2, actualSdHash2)

        // Confirm payment sd_hash == checkout sd_hash (both cover same DPC base, no discs)
        val (_, p1) = decodeJwt(parts[pos1])
        assertEquals(
            "Both mandates have same sd_hash base (parallel roots)",
            p1.getString("sd_hash"), p2.getString("sd_hash")
        )

        println("✓ Payment mandate sd_hash covers DPC only (parallel design)")
        println("  Cross-mandate binding is via checkout_reference field in payment constraints")
    }

    @Test
    fun `both mandates have same sd_hash base in parallel design`() {
        // In the parallel design, both KB-SD-JWTs root in the same DPC base.
        // If no delegate_disclosures differ, sd_hash for both mandates is identical.
        // Each mandate is independently verifiable against the DPC.
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload(), emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(),  emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKeyNormalized).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        val parts = chain.split("~").dropLast(1)
        val kbPositions = parts.indices.filter { it > 0 && parts[it].split(".").size == 3 }
        assertEquals(2, kbPositions.size)

        val (_, kb1Payload) = decodeJwt(parts[kbPositions[0]])
        val (_, kb2Payload) = decodeJwt(parts[kbPositions[1]])

        // Both sd_hashes cover same DPC base (no delegate_disclosures in either proposal here)
        assertEquals(
            "Both parallel mandates root in same DPC base → same sd_hash when no delegate discs differ",
            kb1Payload.getString("sd_hash"),
            kb2Payload.getString("sd_hash")
        )

        // With delegate_disclosures, sd_hashes differ (checkout mandate opens checkout_jwt box)
        val checkoutDisc = "WyJzYWx0IiwiY2hlY2tvdXRfand0IiwiPGp3dD4iXQ"  // fake disclosure
        val proposalsWithDisc = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload(), listOf(checkoutDisc), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(),  emptyList(), listOf(DPC_CRED_ID))
        )
        val chain2 = SdJwt(dpcCredential, holderKeyNormalized).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposalsWithDisc
        )
        val parts2 = chain2.split("~").dropLast(1)
        val kbPos2 = parts2.indices.filter { it > 0 && parts2[it].split(".").size == 3 }
        val (_, kb1WithDisc) = decodeJwt(parts2[kbPos2[0]])
        val (_, kb2WithDisc) = decodeJwt(parts2[kbPos2[1]])

        assertNotEquals(
            "When checkout mandate has delegate_disclosures, its sd_hash differs from payment mandate",
            kb1WithDisc.getString("sd_hash"),
            kb2WithDisc.getString("sd_hash")
        )

        println("✓ Parallel design: mandates share DPC base sd_hash when no delegate discs differ")
        println("  Adding checkout_disc to checkout mandate changes only that mandate's sd_hash")
    }


    companion object {
        /**
         * DPC SD-JWT credential from databasenew.json (dpc_v3_2_sdjwt).
         * issuer_jwt~disc1~...~disc8~   (8 selective disclosures, trailing ~)
         */
        const val DPC_SDJWT_CREDENTIAL =
            "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCIsICJ4NWMiOiBbIk1JSUM1akNDQW8yZ0F3" +
            "SUJBZ0lVRVJjNEQzRVpQY25MdXg2N1ZWZDU4d2lrWGRjd0NnWUlLb1pJemowRUF3SXdlakVMTUFrR0Ex" +
            "VUVCaE1DVlZNeEV6QVJCZ05WQkFnTUNrTmhiR2xtYjNKdWFXRXhGakFVQmdOVkJBY01EVTF2ZFc1MFlX" +
            "bHVJRlpwWlhjeEhEQWFCZ05WQkFvTUUwUnBaMmwwWVd3Z1EzSmxaR1Z1ZEdsaGJITXhJREFlQmdOVkJB" +
            "TU1GMlJwWjJsMFlXd3RZM0psWkdWdWRHbGhiSE11WkdWMk1CNFhEVEkxTURReU5URTBNVEl5TmxvWERU" +
            "STJNRFF5TlRFME1USXlObG93ZWpFTE1Ba0dBMVVFQmhNQ1ZWTXhFekFSQmdOVkJBZ01Da05oYkdsbWIz" +
            "SnVhV0V4RmpBVUJnTlZCQWNNRFUxdmRXNTBZV2x1SUZacFpYY3hIREFhQmdOVkJBb01FMFJwWjJsMFlX" +
            "d2dRM0psWkdWdWRHbGhiSE14SURBZUJnTlZCQU1NRjJScFoybDBZV3d0WTNKbFpHVnVkR2xoYkhNdVpH" +
            "VjJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUV1TGQ1aUhPK05UNlJzNDZwQkFrQWM4" +
            "RW1mb3gvOGtqSXJFclF2UGFBSjMxemRWWEV2a1pPZFFqV0wydy9xblJKZ2c4c2hETnp5RUZ0UENqMTg0" +
            "WExGcU9COERDQjdUQWZCZ05WSFNNRUdEQVdnQlQ2aVpRaFo4NG83Mi9lWGZyZHpxMXBUSTdQQ2pBZEJn" +
            "TlZIUTRFRmdRVWc3ZE1LSjViaElVTnBsS2RmWFlhUkdQQ2dOVXdJZ1lEVlIwUkJCc3dHWUlYWkdsbmFY" +
            "UmhiQzFqY21Wa1pXNTBhV0ZzY3k1a1pYWXdOQVlEVlIwZkJDMHdLekFwb0NlZ0pZWWphSFIwY0hNNkx5" +
            "OWthV2RwZEdGc0xXTnlaV1JsYm5ScFlXeHpMbVJsZGk5amNtd3dLZ1lEVlIwU0JDTXdJWVlmYUhSMGNI" +
            "TTZMeTlrYVdkcGRHRnNMV055WldSbGJuUnBZV3h6TG1SbGRqQU9CZ05WSFE4QkFmOEVCQU1DQjRBd0ZR" +
            "WURWUjBsQVFIL0JBc3dDUVlIS0lHTVhRVUJBakFLQmdncWhrak9QUVFEQWdOSEFEQkVBaUFnR3VXekxp" +
            "dnJGbTRWOU45SEN5Z1ErbHU2am9zN2FlZ0d1N2xaOEs1WFFRSWdLM1N0Rm5nL2YwTTdhcUZGWGs1S0VU" +
            "UTN1UUZtY3JUcVE3eHJwWWF3dTFNPSIsICJNSUlDdVRDQ0FsK2dBd0lCQWdJVVE3aG5TbTNrSWRGdUFO" +
            "YW5GcGs0ekVkeW4xc3dDZ1lJS29aSXpqMEVBd0l3ZWpFTE1Ba0dBMVVFQmhNQ1ZWTXhFekFSQmdOVkJB" +
            "Z01Da05oYkdsbWIzSnVhV0V4RmpBVUJnTlZCQWNNRFUxdmRXNTBZV2x1SUZacFpYY3hIREFhQmdOVkJB" +
            "b01FMFJwWjJsMFlXd2dRM0psWkdWdWRHbGhiSE14SURBZUJnTlZCQU1NRjJScFoybDBZV3d0WTNKbFpH" +
            "VnVkR2xoYkhNdVpHVjJNQjRYRFRJMU1EUXlOVEUwTVRJeU5sb1hEVE0xTURReE16RTBNVEl5Tmxvd2Vq" +
            "RUxNQWtHQTFVRUJoTUNWVk14RXpBUkJnTlZCQWdNQ2tOaGJHbG1iM0p1YVdFeEZqQVVCZ05WQkFjTURV" +
            "MXZkVzUwWVdsdUlGWnBaWGN4SERBYUJnTlZCQW9NRTBScFoybDBZV3dnUTNKbFpHVnVkR2xoYkhNeElE" +
            "QWVCZ05WQkFNTUYyUnBaMmwwWVd3dFkzSmxaR1Z1ZEdsaGJITXVaR1YyTUZrd0V3WUhLb1pJemowQ0FR" +
            "WUlLb1pJemowREFRY0RRZ0FFcUlEL0lLV21UMGVlYmQzaEd5OEIwQ2R6VDlxclliOG5IYVFSNGJFNG5Y" +
            "UVFCSEF3ZFd5bTJqakxmYjVXbzJzSCtSdkZrRkFwUG5tdjBhcFA3SXkwaTZPQndqQ0J2ekFpQmdOVkhS" +
            "RUVHekFaZ2hka2FXZHBkR0ZzTFdOeVpXUmxiblJwWVd4ekxtUmxkakFkQmdOVkhRNEVGZ1FVK29tVUlX" +
            "Zk9LTzl2M2wzNjNjNnRhVXlPendvd0h3WURWUjBqQkJnd0ZvQVUrb21VSVdmT0tPOXYzbDM2M2M2dGFV" +
            "eU96d293RWdZRFZSMFRBUUgvQkFnd0JnRUIvd0lCQURBT0JnTlZIUThCQWY4RUJBTUNBUVl3S2dZRFZS" +
            "MFNCQ013SVlZZmFIUjBjSE02THk5a2FXZHBkR0ZzTFdOeVpXUmxiblJwWVd4ekxtUmxkakFKQmdOVkhS" +
            "OEVBakFBTUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSUEwdFc0ayt1SEFsOXRmNFdOa3NxRVIwT1JLK2pH" +
            "d1NoV2Z2RjJtVzZKenZBaUVBaGhjQUxxNm1sSmd2MThwZnpjZ1B6N3lPMTc1bmxFWTF0ZVlpYVBmWWlu" +
            "cz0iXX0.eyJfc2QiOiBbIjB5Z1NJTWJ5Q3pfU0FMN0NyWmVEZ19DM0FucUpWZ2YzNUkxdDFpZTBSWnMi" +
            "LCAiMWlwU2VqQUF3X2xBU09lTnNHYmozUl8zTVpOUnRhbGdVOU1ZdmM3M1o1ZyIsICIzZF9rc0xhWTdO" +
            "QXl1OVBRWm9kUkI0WHNxRjJqcXVDc2wyYXZPbG5XQ244IiwgIlBCaFc0MkFUSnFjczNfb2RWaEh1VEdF" +
            "RGhON2lkRG1aTUxMT1JSLWxBZWMiLCAiUE5TSlJYekdQY0J5RUwzX2pGbWM0amd6eEpVSnNUbXVESkZv" +
            "amtUeXNEMCIsICJSQVdnNVhmOXFoaVA3N3BiMVI0TVlZLXJWMjExSlRvS3ZBeF9SdzVzUjd3IiwgInBY" +
            "amJuUmpuMjhKUlVKRHcxa3VVOGtIck5HQWZUQXNzazhCTTF5MUlEd0kiLCAieUdYclZnYjlIS0dJVTlu" +
            "NndFVlBkc3hhZmRGSUllVllSZHI3MkRVOWdpTSJdLCAiaXNzIjogImh0dHBzOi8vZGlnaXRhbC1jcmVk" +
            "ZW50aWFscy5kZXYiLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2Y3QiOiAi" +
            "Y29tLmVtdmNvLmRwYyIsICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6" +
            "ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICI4akJXcml1SkJZLS11X18yak9KZmNYNEpqNGtFcVk0" +
            "Q1VYOWNmMWJRZGRZIiwgInkiOiAiY3NIMmtPR2hsZW1oUlJ1UFVZRktKWVpnVnFFWFFoMkpmb3RSS0dS" +
            "TWZMRSJ9fX0.Coglr0YLOqUrjDLP7nBl_OCWggnn8mO_DrL_Oc7XI2R8xHJvA0fzK3nnSns0sDZ_sAvP" +
            "7wbmR28eJj1dk8XmDw~WyJiWk5wbVRlb0w1dFlVN2dLVFZrVFVBIiwgImNhcmRfbGFzdF9mb3VyIiwgI" +
            "jQ0NDQiXQ~WyJXR01wb2pPQWMtcUVfaUV5bUEyUmlRIiwgImNhcmRfYXJ0X3VybCIsICJodHRwczovL3" +
            "BvY2tldGJhbmsuZXhhbXBsZS9jYXJkLnBuZyJd~WyJCdThHaWU5NDluQWdCZEw2QjY1N013IiwgImNhc" +
            "mRfbmV0d29ya19jb2RlIiwgIkFDTUUiXQ~WyJlNVlrMS01RjM2RlNpa2JWUVhCRFh3IiwgImNhcmRfY2" +
            "9iYWRnZWRfbmV0d29ya19jb2RlIiwgIkxBU0VSIl0~WyJ2eklEdUdxOFcxMTcybW5UWUcxOEp3IiwgIm" +
            "NhcmRfYmluIiwgIjk5MDAwMSJd~WyJFbHIxTmV6QVVHTzBLN21UNUNhVDN3IiwgImNhcmRfaWQiLCAiN" +
            "WQ4ZjdlOWMwYTEyIl0~WyIzOGtxMzBtYzZmZ1MxYnVyeTh1UWtnIiwgImNhcmRfcGFyIiwgIjk5MDBBQ" +
            "kMxMjNYWVo3ODlMTU5PUFFSU1RVVldYIl0~WyJNUThsck5rQXdZbGF2TVQ4b3duNERBIiwgImNyZWRlb" +
            "nRpYWxfaWQiLCAiYjNmMWM4YTItNmQ0ZS00ZjlhLTllM2QtOGE3YzJmMWI5ZDM0Il0~"
    }
}
