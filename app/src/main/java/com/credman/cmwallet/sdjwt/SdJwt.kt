package com.credman.cmwallet.sdjwt

import com.credman.cmwallet.decodeBase64UrlNoPadding
import com.credman.cmwallet.toBase64UrlNoPadding
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest
import android.util.Base64
import com.credman.cmwallet.createJWTES256
import com.credman.cmwallet.jwsDeserialization
import com.credman.cmwallet.loadECPrivateKey
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import java.lang.IllegalStateException
import java.security.PrivateKey
import java.time.Instant
import kotlin.collections.iterator
import kotlin.collections.mutableListOf

class SdJwt(
    credential: String,
    holderPrivateKey: String
) {
    val issuerJwt: String
    val disclosures: List<String>
    val holderKey: PrivateKey
    init {
        val composition = credential.split('~')
        issuerJwt = composition[0]
        disclosures =
            if (composition.size <= 1) emptyList()
            else composition.subList(1, composition.size - 1)
        holderKey = loadECPrivateKey(holderPrivateKey.decodeBase64UrlNoPadding())
    }

    val verifiedResult: VerificationResult by lazy {
        verify(issuerJwt, disclosures)
    }

    private fun addDisclosuresToPresentation(sd: JSONObject, ret: MutableList<String>) {
        for (key in sd.keys()) {
            if ("_sd" == key || "..." ==  key) {
                val digest = sd.getString(key)
                val disclosure = verifiedResult.digestDisclosureMap[digest]!!
                ret.add(disclosure)
                val decodedDisclosure = JSONArray(String(disclosure.decodeBase64UrlNoPadding()))
                val disclosureValue = when (decodedDisclosure.length()) {
                    2 -> { // Array item
                         decodedDisclosure.get(1)
                    }
                    3 -> {
                        decodedDisclosure.get(2)
                    }
                    else -> throw IllegalStateException("Unexpected disclosure length: ${decodedDisclosure.length()}")
                }
                when (disclosureValue) {
                    is JSONArray -> {
                        for (arrayIdx in 0..< disclosureValue.length()) {
                            val childSd = disclosureValue.getJSONObject(arrayIdx)
                            addDisclosuresToPresentation(childSd, ret)
                        }
                    }
                    else -> {} // Pass through
                }
            } else {
                val recursiveSd = sd.get(key)
                if (recursiveSd is JSONObject) {addDisclosuresToPresentation(recursiveSd, ret)
                } else {
                    throw IllegalStateException("Unexpected type ${recursiveSd::class.java}")
                }
            }
        }
    }

    @OptIn(ExperimentalSerializationApi::class)
    fun present(
        claimSets: JSONArray?, // If null, match all
        nonce: String,
        aud: String,
        transactionDataHashes: Map<String, List<ByteArray>>
    ): String {
        val sdJwtComponents = mutableListOf(issuerJwt)
        if (claimSets == null) {
            sdJwtComponents.addAll(disclosures)
        } else {
            var claimSetMatched = true
            for (i in 0..<claimSets.length()) {
                claimSetMatched = true
                val claimSet = claimSets[i] as JSONArray
                val ret = mutableListOf<String>()
                for (claimIdx in 0 until claimSet.length()) {
                    // TODO: value match
                    val claim = claimSet.getJSONObject(claimIdx)!!
                    val path = claim.getJSONArray("path")
                    var sd = verifiedResult.sdMap
                    val sds = mutableListOf<JSONObject>()
                    for (pathIdx in 0..<path.length()) {
                        // TODO: handle path variants (null)
                        val currPath = path.getString(pathIdx)
                        if (sd.has(currPath)) {
                            sd = sd.getJSONObject(currPath)
                            sds.add(JSONObject(sd.toString()))
                        } else {
                            claimSetMatched = false
                            break
                        }
                    }
                    if (claimSetMatched) {
                        addDisclosuresToPresentation(sd, ret)
                        // TODO: improve this code
                        if (sds.size > 1) {
                            for (k in 0..<sds.size - 1) {
                                val currSd = sds[k]
                                if (currSd.has("_sd")) {
                                    val digest = currSd.getString("_sd")
                                    val disclosure = verifiedResult.digestDisclosureMap[digest]!!
                                    ret.add(disclosure)
                                }
                            }
                        }
                    } else {
                        break
                    }
                }
                if (claimSetMatched) {
                    sdJwtComponents.addAll(ret)
                    break
                }
            }
            require(claimSetMatched) {"Could not match against any claim sets."}
        }
        val sdJwt = sdJwtComponents.joinToString("~", postfix="~")

        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(sdJwt.encodeToByteArray()).toBase64UrlNoPadding()
        val kbHeader = buildJsonObject {
            put("typ", "kb+jwt")
            put("alg", "ES256")
        }
        val kbPayload = buildJsonObject {
            put("iat", Instant.now().epochSecond)
            put("aud", aud)
            put("nonce", nonce)
            put("sd_hash", digest)
            if (transactionDataHashes.isNotEmpty()) {
                for (transactionData in transactionDataHashes) {
                    putJsonArray(transactionData.key) {
                        transactionData.value.forEach { data ->
                            add(data.toBase64UrlNoPadding())
                        }
                    }
                }
            }
        }
        val kbJwt = createJWTES256(kbHeader, kbPayload, holderKey)
        return sdJwt + kbJwt
    }

    /**
     * Produces a dSD-JWT chain for the HITL AP2 mandate flow.
     *
     * The DPC SD-JWT is presented normally (no KB-JWT from the wallet). Instead, for each
     * [DelegateProposal] the wallet produces a **KB-SD-JWT**: a compact JWT that simultaneously
     * serves as the KB-JWT for the preceding SD-JWT in the chain AND carries the mandate payload
     * (vct, cnf.jwk=agent_key, constraints / checkout_hash, etc.) as its own JWT claims.
     *
     * Chain structure (all parts joined with `~`):
     * ```
     *   dpc_issuer_jwt ~ dpc_disc1 ~ ... ~ checkout_discs ~ KB-SD-JWT_checkout
     *                              ~ payment_discs ~ KB-SD-JWT_payment ~
     * ```
     * - Every KB-SD-JWT is signed with the holder's **device key** (cnf key of the preceding SD-JWT).
     * - `sd_hash` in each KB-SD-JWT covers everything that preceded it (base SD-JWT + earlier parts).
     * - `cnf.jwk` in each KB-SD-JWT's delegate payload = agent's public key (delegatee).
     * - Trailing `~` signals no agent KB-JWT yet; the agent appends that when presenting to a verifier.
     *
     * Verification (per spec):
     *  1. Verify DPC SD-JWT using issuer key; KB = KB-SD-JWT_checkout.
     *  2. For each KB-SD-JWT: verify as SD-JWT+KB using delegate payload as JWT payload and the cnf
     *     key from the preceding SD-JWT. Next KB-SD-JWT (or agent's KB-JWT) is the KB.
     *  3. Final KB-SD-JWT includes transaction binding data (nonce, aud, transaction_data_hashes).
     */
    @OptIn(ExperimentalSerializationApi::class)
    fun presentWithDelegations(
        claimSets: JSONArray?,
        nonce: String,
        aud: String,
        transactionDataHashes: Map<String, List<ByteArray>>,
        delegateProposals: List<com.credman.cmwallet.openid4vp.DelegateProposal>
    ): String {
        require(delegateProposals.isNotEmpty()) {
            "Use present() when there are no delegate proposals"
        }

        // ── Step 1: select DPC disclosures (same logic as present()) ──────────────────
        val selectedDisclosures = mutableListOf<String>()
        if (claimSets == null) {
            selectedDisclosures.addAll(disclosures)
        } else {
            var matched = false
            outer@ for (i in 0..<claimSets.length()) {
                val claimSet = claimSets[i] as JSONArray
                val ret = mutableListOf<String>()
                var ok = true
                for (claimIdx in 0 until claimSet.length()) {
                    val claim = claimSet.getJSONObject(claimIdx)
                    val path = claim.getJSONArray("path")
                    var sd = verifiedResult.sdMap
                    val sds = mutableListOf<JSONObject>()
                    for (pathIdx in 0..<path.length()) {
                        val currPath = path.getString(pathIdx)
                        if (sd.has(currPath)) {
                            sd = sd.getJSONObject(currPath)
                            sds.add(JSONObject(sd.toString()))
                        } else { ok = false; break }
                    }
                    if (!ok) break
                    addDisclosuresToPresentation(sd, ret)
                    if (sds.size > 1) {
                        for (k in 0..<sds.size - 1) {
                            val currSd = sds[k]
                            if (currSd.has("_sd")) {
                                val digest = currSd.getString("_sd")
                                ret.add(verifiedResult.digestDisclosureMap[digest]!!)
                            }
                        }
                    }
                }
                if (ok) { selectedDisclosures.addAll(ret); matched = true; break@outer }
            }
            require(matched) { "Could not match against any claim sets." }
        }

        // ── Step 2: build the running component list ──────────────────────────────────
        // Parts accumulate here; they are joined with `~` to form the chain.
        val parts = mutableListOf<String>()
        parts.add(issuerJwt)
        parts.addAll(selectedDisclosures)

        // ── Step 3: for each delegate proposal, append its disclosures then a KB-SD-JWT ─
        val isLast = { idx: Int -> idx == delegateProposals.lastIndex }

        for ((idx, proposal) in delegateProposals.withIndex()) {
            // Append the delegate's own selective disclosures (for claims like checkout_jwt)
            parts.addAll(proposal.delegateDisclosures)

            // sd_hash covers the entire preceding chain: parts.joinToString("~") + "~"
            val precedingChain = parts.joinToString("~", postfix = "~")
            val sdHash = MessageDigest.getInstance("SHA-256")
                .digest(precedingChain.encodeToByteArray())
                .toBase64UrlNoPadding()

            // Build KB-SD-JWT header: typ="kb+jwt" (it IS a KB-JWT for the preceding SD-JWT)
            val kbSdHeader = buildJsonObject {
                put("typ", "kb+jwt")
                put("alg", "ES256")
            }

            // Build KB-SD-JWT payload = delegate_payload claims + standard KB fields
            // The delegate_payload already carries: vct, cnf.jwk (agent key), constraints etc.
            val kbSdPayload = buildJsonObject {
                // KB standard fields
                put("iat", Instant.now().epochSecond)
                put("aud", aud)
                put("nonce", nonce)
                put("sd_hash", sdHash)

                // Mandate / delegate fields from the proposal (verbatim copy)
                for (key in proposal.delegatePayload.keys()) {
                    put(key, anyToJsonElement(proposal.delegatePayload.get(key)))
                }

                // Transaction data hashes go in the LAST KB-SD-JWT only
                if (isLast(idx) && transactionDataHashes.isNotEmpty()) {
                    for (entry in transactionDataHashes) {
                        putJsonArray(entry.key) {
                            entry.value.forEach { data -> add(data.toBase64UrlNoPadding()) }
                        }
                    }
                }
            }

            val kbSdJwt = createJWTES256(kbSdHeader, kbSdPayload, holderKey)
            parts.add(kbSdJwt)
        }

        // ── Step 4: return chain with trailing ~ (no agent KB-JWT yet) ────────────────
        return parts.joinToString("~", postfix = "~")
    }

    /** Converts an org.json value to a kotlinx.serialization JsonElement. */
    private fun anyToJsonElement(v: Any?): kotlinx.serialization.json.JsonElement = when (v) {
        null, JSONObject.NULL -> kotlinx.serialization.json.JsonNull
        is Boolean -> kotlinx.serialization.json.JsonPrimitive(v)
        is Int -> kotlinx.serialization.json.JsonPrimitive(v)
        is Long -> kotlinx.serialization.json.JsonPrimitive(v)
        is Double -> kotlinx.serialization.json.JsonPrimitive(v)
        is Float -> kotlinx.serialization.json.JsonPrimitive(v)
        is String -> kotlinx.serialization.json.JsonPrimitive(v)
        is JSONObject -> {
            val map = mutableMapOf<String, kotlinx.serialization.json.JsonElement>()
            for (k in v.keys()) map[k] = anyToJsonElement(v.get(k))
            kotlinx.serialization.json.JsonObject(map)
        }
        is JSONArray -> {
            val list = (0 until v.length()).map { anyToJsonElement(v.get(it)) }
            kotlinx.serialization.json.JsonArray(list)
        }
        else -> kotlinx.serialization.json.JsonPrimitive(v.toString())
    }

}

class VerificationResult(
    val processedJwt: JSONObject,
    val digestDisclosureMap: Map<String, String>, // Digest to encoded disclosure
    val sdMap: JSONObject,
)

fun verify(issuerJwtSerialization: String, disclosures: List<String>): VerificationResult {
    val issuerJwt = IssuerJwt(issuerJwtSerialization)

    if (issuerJwt.payload.has("_sd_alg")) {
        assert(issuerJwt.payload["_sd_alg"] == "sha-256") {"Only support sha-256"}
    }

    val digestDisclosureMap = mutableMapOf<String, JSONArray>()
    val finalDigestDisclosureMap = mutableMapOf<String, String>()
    for (disclosure in disclosures) {
        val decoded = disclosure.decodeBase64UrlNoPadding().decodeToString()
        val disclosureJson = JSONArray(decoded)
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(disclosure.encodeToByteArray()).toBase64UrlNoPadding()
        digestDisclosureMap[digest] = disclosureJson
        finalDigestDisclosureMap[digest] = disclosure
    }
    val sdMap = JSONObject() // TODO: handle array elements
    val processedJwt = verifyInternal(issuerJwt.payload, digestDisclosureMap, mutableSetOf(), sdMap) as JSONObject
    assert(digestDisclosureMap.isEmpty()) { "All disclosures must be referenced in the issuer jwt" }
    processedJwt.remove("_sd_alg")
    return VerificationResult(processedJwt, finalDigestDisclosureMap, sdMap)
}

private fun verifyInternal(
    input: Any,
    digestDisclosureMap: MutableMap<String, JSONArray>,
    seenDigest: MutableSet<String>,
    sdMap: JSONObject
): Any {
    when (input) {
        is JSONObject -> {
            val processed = JSONObject()
            for (k in input.keys()) {
                val v = input.get(k)
                if (k == "_sd") {
                    val sdDigests = v as JSONArray
                    for (i in 0..<sdDigests.length()) {
                        val digest = sdDigests[i] as String
                        assert(!seenDigest.contains(digest)) { "Digest seen more than once: $digest" }
                        seenDigest.add(digest)
                        val disclosure = digestDisclosureMap.remove(digest)
                        if (disclosure != null) {
                            assert(disclosure.length() == 3) { "Validation failed: Invalid disclosure length. expected: 3" }
                            val claimName = disclosure[1] as String
                            assert(claimName != "_sd") { "Validation failed: claim name cannot be _sd"}
                            assert(claimName != "...") { "Validation failed: claim name cannot be ..."}
                            assert(!input.has(claimName)) { "Validation failed: claim name $claimName already exists"}
                            val claimValue = disclosure[2]
                            val childJson = JSONObject()
                            childJson.put("_sd", digest)
                            sdMap.put(claimName, childJson)
                            processed.put(claimName, verifyInternal(claimValue, digestDisclosureMap, seenDigest, childJson))
                        }
                    }
                } else {
                    val childJson = JSONObject()
                    sdMap.put(k, childJson)
                    processed.put(k, verifyInternal(v, digestDisclosureMap, seenDigest, childJson))
                }
            }
            return processed
        }
        is JSONArray -> {
            val processed = JSONArray()
            for (i in 0..<input.length()) {
                val arrElement = input[i]
                if (arrElement is JSONObject && arrElement.length() == 1 && arrElement.has("...")) {
                    val digest = arrElement["..."] as String
                    assert(!seenDigest.contains(digest)) { "Digest seen more than once: $digest" }
                    seenDigest.add(digest)
                    val disclosure = digestDisclosureMap.remove(digest)
                    if (disclosure != null) {
                        assert(disclosure.length() == 2) { "Validatiodn failed: Invalid disclosure length. expected: 2" }
                        val claimValue = disclosure[1]
                        processed.put(verifyInternal(claimValue, digestDisclosureMap, seenDigest, sdMap))
                    }
                } else {
                    processed.put(verifyInternal(arrElement, digestDisclosureMap, seenDigest, sdMap))
                }
            }
            return processed
        }
        else -> return input
    }
}

class IssuerJwt {
    var header: JSONObject = JSONObject()
    var payload: JSONObject = JSONObject()
    private lateinit var signature: ByteArray
    private var sourceCompactSerialization: String? = null

    constructor(compactSerialization: String) {
        sourceCompactSerialization = compactSerialization
        val components = compactSerialization.split('.')
        header = JSONObject(String(components[0].decodeBase64UrlNoPadding()))
        payload = JSONObject(String(components[1].decodeBase64UrlNoPadding()))
        signature = jwsSignatureToDer(components[2], 256)

        validateIssuerJwt()
    }

    fun validateIssuerJwt() {
        require(header["typ"] == "dc+sd-jwt")
        require(header["alg"] == "ES256") { "Unsupported agl ${header["alg"]}" }
        require(payload.has("iss"))
        require(payload.has("iat"))
        require(payload.has("cnf"))
        require(payload.has("vct"))

        jwsDeserialization(sourceCompactSerialization!!)

        // TODO: The iss value MUST be an URL with a FQDN matching a dNSName Subject Alternative Name
        // (SAN) [RFC5280] entry in the leaf certificate.
    }
}

fun jwsSignatureToDer(jwsSignature: String, keySizeInBits: Int): ByteArray {
    val decodedSignature = Base64.decode(jwsSignature, Base64.URL_SAFE)
    val componentLength = keySizeInBits / 8

    if (decodedSignature.size != componentLength * 2) {
        throw IllegalArgumentException("Invalid signature length")
    }

    val r = decodedSignature.copyOfRange(0, componentLength)
    val s = decodedSignature.copyOfRange(componentLength, componentLength * 2)

    val rBigInt = BigInteger(1, r)
    val sBigInt = BigInteger(1, s)

    val derStream = ByteArrayOutputStream()
    derStream.write(0x30) // SEQUENCE tag

    val sequenceContent = ByteArrayOutputStream()
    encodeInteger(sequenceContent, rBigInt)
    encodeInteger(sequenceContent, sBigInt)

    val sequenceBytes = sequenceContent.toByteArray()
    derStream.write(encodeLength(sequenceBytes.size))
    derStream.write(sequenceBytes)

    return derStream.toByteArray()
}

private fun encodeInteger(stream: ByteArrayOutputStream, value: BigInteger) {
    val valueBytes = value.toByteArray()
    stream.write(0x02) // INTEGER tag
    stream.write(encodeLength(valueBytes.size))
    stream.write(valueBytes)
}

private fun encodeLength(length: Int): ByteArray {
    return if (length < 128) {
        byteArrayOf(length.toByte())
    } else {
        val lengthBytes = (Math.log(length.toDouble()) / Math.log(256.0)).toInt() + 1
        val buffer = ByteBuffer.allocate(lengthBytes + 1)
        buffer.put((0x80 or lengthBytes).toByte())
        for (i in lengthBytes - 1 downTo 0) {
            buffer.put((length shr (8 * i)).toByte())
        }
        buffer.array()
    }
}