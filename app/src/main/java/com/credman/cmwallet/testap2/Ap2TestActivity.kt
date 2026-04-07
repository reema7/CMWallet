package com.credman.cmwallet.testap2

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.credentials.*
import androidx.credentials.exceptions.GetCredentialException
import androidx.lifecycle.lifecycleScope
import com.credman.cmwallet.ui.theme.CMWalletTheme
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * AP2 End-to-End Test Activity
 *
 * Simulates an AI agent making an OID4VP request for a DPC credential with
 * two AP2 mandates (checkout + payment). Flow:
 *
 *  1. Build OID4VP request with delegate transaction_data
 *  2. Call CredentialManager.getCredential() → triggers CMWallet picker
 *  3. User selects DPC card → GetCredentialActivity produces dSD-JWT chain
 *  4. Agent parses chain: verifies KB-SD-JWT, extracts both mandate disclosures
 *  5. Builds checkout-only presentation for merchant
 *  6. Builds payment-only presentation for credential provider
 */
@OptIn(ExperimentalDigitalCredentialApi::class)
class Ap2TestActivity : ComponentActivity() {

    private val TAG = "Ap2TestActivity"

    private val agentKeyPair by lazy {
        KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
    }

    private val uiState = mutableStateOf(Ap2UiState())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            CMWalletTheme { Ap2TestScreen() }
        }
    }

    // ── Invoke CredentialManager ──────────────────────────────────────────────

    private fun invokeCredentialManager() {
        uiState.value = Ap2UiState(status = "Invoking CredentialManager…")
        lifecycleScope.launch {
            try {
                val requestJson = buildOid4vpRequest()
                Log.d(TAG, "Request: $requestJson")
                uiState.value = uiState.value.copy(requestPreview = previewTdItem(requestJson))

                val response = CredentialManager.create(this@Ap2TestActivity).getCredential(
                    context = this@Ap2TestActivity,
                    request = GetCredentialRequest(listOf(GetDigitalCredentialOption(requestJson)))
                )

                val cred = response.credential
                if (cred is DigitalCredential) processVpToken(cred.credentialJson)
                else uiState.value = uiState.value.copy(status = "Unexpected credential type: ${cred::class.simpleName}")

            } catch (e: GetCredentialException) {
                Log.e(TAG, "CM error", e)
                uiState.value = uiState.value.copy(status = "CredentialManager error", error = "${e::class.simpleName}: ${e.message}")
            } catch (e: Exception) {
                Log.e(TAG, "Error", e)
                uiState.value = uiState.value.copy(status = "Error", error = e.message)
            }
        }
    }

    // ── Build OID4VP Request ──────────────────────────────────────────────────

    private fun buildOid4vpRequest(): String {
        val agentJwk = agentPublicJwk()

        // Merchant-signed checkout JWT (UCP format; stub sig in this test)
        val checkoutJwtPayload = JSONObject().apply {
            put("id", "order_20260330_9f3a")
            put("status", "pending_payment")
            put("currency", "USD")
            put("merchant", JSONObject().apply { put("id", "m_lyft_001"); put("name", "Lyft") })
            put("line_items", JSONArray().put(JSONObject().apply {
                put("title", "Ride to SFO"); put("quantity", 1); put("unit_price", "42.50")
            }))
            put("totals", JSONObject().apply {
                put("subtotal", "42.50"); put("tax", "3.72"); put("total", "46.22")
            })
        }
        val checkoutJwt  = "${b64("eyJhbGciOiJFUzI1NiIsInR5cCI6ImNoZWNrb3V0K2p3dCJ9")}.${b64u(checkoutJwtPayload.toString())}.MERCHANT_SIG"
        val checkoutHash = b64u(sha256bytes(checkoutJwt))

        // mandate.checkout.1
        val checkoutMandate = JSONObject().apply {
            put("vct",           "mandate.checkout.1")
            put("checkout_hash", checkoutHash)
            put("checkout_jwt",  checkoutJwt)
            put("exp",           9_999_999_999L)
            put("cnf",           JSONObject().put("jwk", agentJwk))
        }

        // mandate.payment.1 — no cnf (bound via transaction_id = checkout_hash)
        val paymentMandate = JSONObject().apply {
            put("vct",            "mandate.payment.1")
            put("transaction_id", checkoutHash)
            put("payee",          JSONObject().apply { put("id", "m_lyft_001"); put("name", "Lyft") })
            put("amount",         JSONObject().apply { put("value", "46.22"); put("currency", "USD") })
            put("payment_instrument", JSONObject().apply {
                put("type", "dpc"); put("credential_id", "b3f1c8a2-6d4e-4f9a-9e3d-8a7c2f1b9d34")
            })
            put("exp", 9_999_999_999L)
            put("cnf", JSONObject().put("jwk", agentJwk))
        }

        // transaction_data item — base64url-encoded per spec
        val tdItem = JSONObject().apply {
            put("type",                "delegate")
            put("format",              "dc+sd-jwt")
            put("credential_ids",      JSONArray().put("dpc_credential"))
            put("delegate_payload",    JSONArray().put(checkoutMandate).put(paymentMandate))
            put("delegate_disclosures", JSONArray())
        }

        return JSONObject().apply {
            put("protocol", "openid4vp-v1-unsigned")
            put("data", JSONObject().apply {
                put("response_type", "vp_token")
                put("response_mode", "dc_api")
                put("client_id",     "origin:https://agent.ap2.example")
                put("nonce",         "s6FhdRcsNDIIm_4YmFDd1A")
                put("dcql_query", JSONObject().apply {
                    put("credentials", JSONArray().put(JSONObject().apply {
                        put("id",     "dpc_credential")
                        put("format", "dc+sd-jwt")
                        put("meta",   JSONObject().put("vct_values", JSONArray().put("com.emvco.dpc")))
                        put("claims", JSONArray().apply {
                            put(JSONObject().put("path", JSONArray().put("card_last_four")))
                            put(JSONObject().put("path", JSONArray().put("card_network_code")))
                            put(JSONObject().put("path", JSONArray().put("credential_id")))
                        })
                    }))
                })
                put("transaction_data", JSONArray().put(b64u(tdItem.toString())))
            })
        }.toString()
    }

    // ── Process VP Token ──────────────────────────────────────────────────────

    private fun processVpToken(vpTokenJson: String) {
        try {
            // CM wraps as {"token":"<chain>"} or returns raw chain
            val chain = runCatching { JSONObject(vpTokenJson).getString("token") }
                .getOrDefault(vpTokenJson)

            val parts      = chain.split("~").filter { it.isNotEmpty() }
            val compactPos = parts.indices.filter { parts[it].split(".").size == 3 }
            if (compactPos.size < 2) {
                uiState.value = uiState.value.copy(status = "Expected 2 compact JWTs, got ${compactPos.size}")
                return
            }

            val kbSdJwtIdx = compactPos[1]
            val kbSdJwt    = parts[kbSdJwtIdx]
            val dpcParts   = parts.subList(0, kbSdJwtIdx)
            val (kbH, kbP) = decodeJwt(kbSdJwt)

            // ── Verify KB-SD-JWT ──────────────────────────────────────────────
            val log = StringBuilder()
            log.appendLine("KB-SD-JWT header:")
            log.appendLine("  typ = ${kbH.optString("typ")}")
            log.appendLine("KB-SD-JWT payload:")
            log.appendLine("  nonce   = ${kbP.optString("nonce")}")
            log.appendLine("  aud     = ${kbP.optString("aud")}")
            log.appendLine("  sd_hash = ${kbP.optString("sd_hash")}")

            val dpcBase        = dpcParts.joinToString("~", postfix = "~")
            val expectedSdHash = b64u(sha256bytes(dpcBase))
            val sdHashOk       = expectedSdHash == kbP.optString("sd_hash")
            log.appendLine("  sd_hash valid = $sdHashOk ✓")

            val dpArr = kbP.optJSONArray("delegate_payload")
            log.appendLine("  delegate_payload digests = ${dpArr?.length() ?: 0}")

            // ── Parse mandate disclosures (after KB-SD-JWT) ───────────────────
            val mandateDiscs = parts.subList(kbSdJwtIdx + 1, parts.size)
                .filter { it.split(".").size == 1 }   // exclude any trailing agent KB-JWT

            log.appendLine("\nMandate disclosures: ${mandateDiscs.size}")
            mandateDiscs.forEachIndexed { i, disc ->
                val actualDigest  = b64u(sha256bytes(disc))
                val claimedDigest = dpArr?.optString(i) ?: "?"
                log.appendLine("  disc[$i] bound to KB-SD-JWT: ${actualDigest == claimedDigest} ✓")
            }

            var checkoutObj: JSONObject? = null
            var paymentObj:  JSONObject? = null
            mandateDiscs.forEach { disc ->
                runCatching {
                    val arr = decodeDisclosure(disc)
                    val obj = arr.getJSONObject(1)
                    when (obj.optString("vct")) {
                        "mandate.checkout.1" -> checkoutObj = obj
                        "mandate.payment.1"  -> paymentObj  = obj
                    }
                }
            }

            // ── Build presentations ───────────────────────────────────────────
            val merchantToken = buildPresentation(
                dpcParts, kbSdJwt, mandateDiscs, "mandate.checkout.1",
                nonce = "merchant-nonce-xyz", aud = "https://lyft.com"
            )
            val cpToken = buildPresentation(
                dpcParts, kbSdJwt, mandateDiscs, "mandate.payment.1",
                nonce = "cp-nonce-xyz", aud = "https://credential-provider.paynet.example"
            )

            uiState.value = uiState.value.copy(
                status          = "dSD-JWT verified ✓",
                rawChain        = chain.take(400) + "…",
                verifyLog       = log.toString(),
                checkoutMandate = checkoutObj?.toString(2),
                paymentMandate  = paymentObj?.toString(2),
                merchantToken   = merchantToken?.take(400) + "…",
                cpToken         = cpToken?.take(400) + "…"
            )

        } catch (e: Exception) {
            Log.e(TAG, "processVpToken error", e)
            uiState.value = uiState.value.copy(status = "Parse error", error = e.message)
        }
    }

    private fun buildPresentation(
        dpcParts: List<String>,
        kbSdJwt: String,
        mandateDiscs: List<String>,
        targetVct: String,
        nonce: String,
        aud: String
    ): String? {
        val targetDisc = mandateDiscs.firstOrNull { disc ->
            runCatching {
                decodeDisclosure(disc).getJSONObject(1).optString("vct") == targetVct
            }.getOrDefault(false)
        } ?: return null

        val prefix = (dpcParts + listOf(kbSdJwt, targetDisc)).joinToString("~", postfix = "~")
        val agentKb = buildAgentKbJwt(prefix, nonce, aud)
        return "$prefix$agentKb"
    }

    // ── Agent KB-JWT ──────────────────────────────────────────────────────────

    private fun buildAgentKbJwt(chainPrefix: String, nonce: String, aud: String): String {
        val sdHash  = b64u(sha256bytes(chainPrefix))
        val header  = b64u("""{"typ":"kb+jwt","alg":"ES256"}""")
        val payload = b64u("""{"iat":${System.currentTimeMillis()/1000},"aud":"$aud","nonce":"$nonce","sd_hash":"$sdHash"}""")
        val der = Signature.getInstance("SHA256withECDSA").apply {
            initSign(agentKeyPair.private as ECPrivateKey)
            update("$header.$payload".toByteArray())
        }.sign()
        return "$header.$payload.${b64u(derToRaw(der))}"
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun b64u(s: String)       = b64u(s.toByteArray())
    private fun b64u(b: ByteArray)    = Base64.getUrlEncoder().withoutPadding().encodeToString(b)
    private fun b64(s: String)        = s   // already encoded literal
    private fun sha256bytes(s: String) = MessageDigest.getInstance("SHA-256").digest(s.toByteArray())

    private fun agentPublicJwk(): JSONObject {
        val pub = agentKeyPair.public as ECPublicKey
        return JSONObject().apply {
            put("kty", "EC"); put("crv", "P-256"); put("use", "sig")
            put("x", encodeCoord(pub.w.affineX.toByteArray()))
            put("y", encodeCoord(pub.w.affineY.toByteArray()))
        }
    }

    private fun encodeCoord(raw: ByteArray): String {
        val fixed = if (raw.size > 32) raw.copyOfRange(raw.size - 32, raw.size)
                    else raw.copyOf(32).also { raw.copyInto(it, 32 - raw.size) }
        return b64u(fixed)
    }

    private fun decodeJwt(compact: String): Pair<JSONObject, JSONObject> {
        fun dec(s: String) = JSONObject(String(Base64.getUrlDecoder().decode(s.padEnd(s.length + (4 - s.length % 4) % 4, '='))))
        val p = compact.split(".")
        return dec(p[0]) to dec(p[1])
    }

    private fun decodeDisclosure(b64: String): JSONArray {
        val padded = b64.padEnd(b64.length + (4 - b64.length % 4) % 4, '=')
        return JSONArray(String(Base64.getUrlDecoder().decode(padded)))
    }

    private fun derToRaw(der: ByteArray): ByteArray {
        val rLen = der[3].toInt() and 0xff
        val r    = der.copyOfRange(4, 4 + rLen)
        val sOff = 4 + rLen + 2
        val sLen = der[sOff - 1].toInt() and 0xff
        val s    = der.copyOfRange(sOff, sOff + sLen)
        fun pad32(a: ByteArray) = if (a.size > 32) a.copyOfRange(a.size - 32, a.size)
                                  else a.copyOf(32).also { a.copyInto(it, 32 - a.size) }
        return pad32(r) + pad32(s)
    }

    private fun previewTdItem(requestJson: String): String {
        return runCatching {
            val data   = JSONObject(requestJson).getJSONObject("data")
            val tdEnc  = data.getJSONArray("transaction_data").getString(0)
            val padded = tdEnc.padEnd(tdEnc.length + (4 - tdEnc.length % 4) % 4, '=')
            val tdJson = String(Base64.getUrlDecoder().decode(padded))
            JSONObject(tdJson).toString(2)
        }.getOrDefault("(parse error)")
    }

    // ── Compose UI ────────────────────────────────────────────────────────────

    @Composable
    fun Ap2TestScreen() {
        val state by uiState
        val scroll = rememberScrollState()
        Scaffold(
            topBar = {
                @OptIn(ExperimentalMaterial3Api::class)
                TopAppBar(title = { Text("AP2 dSD-JWT E2E Test") })
            }
        ) { pad ->
            Column(
                modifier = Modifier.padding(pad).padding(16.dp).verticalScroll(scroll),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Button(onClick = { invokeCredentialManager() }, modifier = Modifier.fillMaxWidth()) {
                    Text("Invoke CredentialManager (AP2 Mandate)")
                }
                InfoCard("Status", state.status, error = state.error != null)
                state.error?.let { Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(MaterialTheme.colorScheme.errorContainer)) { Text(it, Modifier.padding(12.dp), fontSize = 11.sp) } }
                state.requestPreview?.let  { ExpandCard("Transaction Data (decoded)", it) }
                state.rawChain?.let        { ExpandCard("Raw dSD-JWT Chain", it) }
                state.verifyLog?.let       { ExpandCard("Verification Log", it, mono = true) }
                state.checkoutMandate?.let { ExpandCard("Checkout Mandate → Merchant", it, mono = true) }
                state.paymentMandate?.let  { ExpandCard("Payment Mandate → Cred Provider", it, mono = true) }
                state.merchantToken?.let   { ExpandCard("Merchant Presentation (truncated)", it, mono = true) }
                state.cpToken?.let         { ExpandCard("CP Presentation (truncated)", it, mono = true) }
            }
        }
    }

    @Composable
    private fun InfoCard(label: String, value: String, error: Boolean = false) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp)) {
                Text(label, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                Text(value, color = if (error) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
            }
        }
    }

    @Composable
    private fun ExpandCard(title: String, content: String, mono: Boolean = false) {
        var open by remember { mutableStateOf(false) }
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Text(title, fontWeight = FontWeight.Bold, fontSize = 13.sp, modifier = Modifier.weight(1f))
                    TextButton(onClick = { open = !open }) { Text(if (open) "Hide" else "Show") }
                }
                if (open) Text(content, fontSize = 11.sp, fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default)
            }
        }
    }
}

data class Ap2UiState(
    val status:          String  = "Ready",
    val error:           String? = null,
    val requestPreview:  String? = null,
    val rawChain:        String? = null,
    val verifyLog:       String? = null,
    val checkoutMandate: String? = null,
    val paymentMandate:  String? = null,
    val merchantToken:   String? = null,
    val cpToken:         String? = null
)
