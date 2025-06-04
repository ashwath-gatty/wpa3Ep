package com.sonimtech.wificonfig

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.wifi.WifiEnterpriseConfig
import android.net.wifi.WifiManager
import android.net.wifi.WifiNetworkSuggestion
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.security.keystore.KeyProperties
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.sonimtech.wificonfig.R
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class MainActivity : AppCompatActivity() {

    private lateinit var etSsid: EditText
    private lateinit var etIdentity: EditText
    private lateinit var etAnonymousIdentity: EditText // Added for Anonymous Identity
    private lateinit var etDomainSuffixMatch: EditText // Added for Domain Suffix Match
    private lateinit var btnPickCaCert: Button
    private lateinit var tvCaCertPath: TextView
    private lateinit var btnPickClientCert: Button
    private lateinit var tvClientCertPath: TextView
    private lateinit var etClientCertPassword: EditText
    private lateinit var btnConfigureWifi: Button
    private lateinit var tvStatus: TextView

    private var caCertUri: Uri? = null
    private var clientCertUri: Uri? = null

    private var caCertificate: X509Certificate? = null
    private var clientCertificate: X509Certificate? = null
    private var clientPrivateKey: PrivateKey? = null

    companion object {
        private const val TAG = "WifiConfigurator"
    }

    // ActivityResultLauncher for picking CA certificate
    private val pickCaCertLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                result.data?.data?.also { uri ->
                    caCertUri = uri
                    tvCaCertPath.text = "CA Cert: ${uri.path}"
                    try {
                        contentResolver.openInputStream(uri)?.use { inputStream ->
                            caCertificate = parseX509Certificate(inputStream)
                            if (caCertificate != null) {
                                Log.i(TAG, "CA Certificate loaded successfully.")
                                Toast.makeText(this, "CA Certificate loaded", Toast.LENGTH_SHORT).show()
                            } else {
                                throw Exception("Failed to parse CA certificate")
                            }
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Error loading CA certificate", e)
                        tvStatus.text = "Error loading CA cert: ${e.message}"
                        caCertUri = null
                        caCertificate = null
                        tvCaCertPath.text = "No CA certificate selected"
                    }
                }
            }
        }

    // ActivityResultLauncher for picking client certificate
    private val pickClientCertLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                result.data?.data?.also { uri ->
                    clientCertUri = uri
                    tvClientCertPath.text = "Client Cert: ${uri.path}"
                    // Password for client cert will be used during configuration
                    Toast.makeText(this, "Client Certificate selected. Enter password.", Toast.LENGTH_LONG).show()
                }
            }
        }


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main) // Ensure this matches your layout file name

        etSsid = findViewById(R.id.etSsid)
        etIdentity = findViewById(R.id.etIdentity)
        etAnonymousIdentity = findViewById(R.id.etAnonymousIdentity) // Added for Anonymous Identity
        etDomainSuffixMatch = findViewById(R.id.etDomainSuffixMatch) // Added for Domain Suffix Match
        btnPickCaCert = findViewById(R.id.btnPickCaCert)
        tvCaCertPath = findViewById(R.id.tvCaCertPath)
        btnPickClientCert = findViewById(R.id.btnPickClientCert)
        tvClientCertPath = findViewById(R.id.tvClientCertPath)
        etClientCertPassword = findViewById(R.id.etClientCertPassword)
        btnConfigureWifi = findViewById(R.id.btnConfigureWifi)
        tvStatus = findViewById(R.id.tvStatus)

        btnPickCaCert.setOnClickListener {
            openFilePicker(arrayOf("application/x-x509-ca-cert", "application/pkix-cert", "text/plain"), pickCaCertLauncher)
        }

        btnPickClientCert.setOnClickListener {
            openFilePicker(arrayOf("application/x-pkcs12"), pickClientCertLauncher) // .pfx, .p12
        }

        btnConfigureWifi.setOnClickListener {
            configureWifi()
        }
    }

    private fun openFilePicker(mimeTypes: Array<String>, launcher: androidx.activity.result.ActivityResultLauncher<Intent>) {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*" // Generic type, then filter with mimeTypes if needed by system picker
            if (mimeTypes.isNotEmpty()) {
                putExtra(Intent.EXTRA_MIME_TYPES, mimeTypes)
            }
        }
        try {
            launcher.launch(intent)
        } catch (e: Exception) {
            Log.e(TAG, "Cannot open file picker", e)
            Toast.makeText(this, "Error: Cannot open file picker. Do you have a file manager installed?", Toast.LENGTH_LONG).show()
        }
    }

    private fun parseX509Certificate(inputStream: InputStream): X509Certificate? {
        Log.d(TAG, "Attempting to parse X.509 certificate.")
        return try {
            val certificateFactory = CertificateFactory.getInstance("X.509")
            val cert = certificateFactory.generateCertificate(inputStream) as X509Certificate
            Log.i(TAG, "Successfully parsed X.509 certificate: Subject='${cert.subjectDN?.name}', Issuer='${cert.issuerDN?.name}', NotBefore='${cert.notBefore}', NotAfter='${cert.notAfter}'")
            cert
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse X.509 certificate: ${e.message}", e)
            null
        }
    }

    private fun loadClientPkcs12(uri: Uri, password: CharArray): Boolean {
        Log.d(TAG, "Attempting to load PKCS12 client certificate from URI: $uri")
        try {
            contentResolver.openInputStream(uri)?.use { inputStream ->
                val keyStore = KeyStore.getInstance("PKCS12")
                keyStore.load(inputStream, password) // This can throw IOException for wrong password or corrupted file
                // It's good practice to clear the password from memory after it's used.
                password.fill(' ')
                val aliases = keyStore.aliases()
                if (aliases.hasMoreElements()) {
                    val alias = aliases.nextElement()
                    Log.i(TAG, "Found alias in PKCS12 file: $alias")
                    clientPrivateKey = keyStore.getKey(alias, password) as? PrivateKey
                    val loadedCert = keyStore.getCertificate(alias) as? X509Certificate

                    if (clientPrivateKey != null && loadedCert != null) {
                        clientCertificate = loadedCert
                        Log.i(TAG, "Successfully loaded client key and certificate from PKCS12. Alias: '$alias'. Certificate: Subject='${clientCertificate!!.subjectDN?.name}', Issuer='${clientCertificate!!.issuerDN?.name}', NotBefore='${clientCertificate!!.notBefore}', NotAfter='${clientCertificate!!.notAfter}'")
                        return true
                    } else {
                        Log.e(TAG, "Failed to extract key/certificate from PKCS12 for alias '$alias'. PrivateKey null: ${clientPrivateKey == null}, Certificate null: ${loadedCert == null}")
                        if (clientPrivateKey == null) Log.d(TAG, "Private key was null after extraction attempt.")
                        if (loadedCert == null) Log.d(TAG, "Client certificate (loadedCert) was null after extraction attempt from alias '$alias'.")
                        tvStatus.text = "Error: Could not extract key/cert from P12. Check file content."
                        return false
                    }
                } else {
                    Log.e(TAG, "No aliases found in PKCS12 keystore. File might be empty or not a valid PKCS12.")
                    tvStatus.text = "Error: No aliases found in P12 file."
                    return false
                }
            } ?: run {
                Log.e(TAG, "Failed to open input stream for client certificate URI: $uri")
                tvStatus.text = "Error: Could not open client cert file."
                return false
            }
        } catch (e: java.io.IOException) {
            Log.e(TAG, "Error loading PKCS12 client certificate - Possible password issue or corrupted file: ${e.message}", e)
            password.fill(' ') // Clear password on exception
            tvStatus.text = "Error: Keystore password incorrect or file corrupted."
            return false
        } catch (e: Exception) {
            Log.e(TAG, "Generic error loading PKCS12 client certificate: ${e.message}", e)
            password.fill(' ') // Clear password on exception
            tvStatus.text = "Error loading client cert: ${e.message}"
            return false
        }
    }


    @SuppressLint("MissingPermission") // Permissions are checked before calling
    private fun configureWifi() {
        val ssid = etSsid.text.toString().trim()
        val identity = etIdentity.text.toString().trim()
        val anonymousIdentity = etAnonymousIdentity.text.toString().trim() // Read Anonymous Identity
        val domainSuffixMatch = etDomainSuffixMatch.text.toString().trim() // Read Domain Suffix Match
        val clientCertPass = etClientCertPassword.text.toString() // DO NOT log this in production
        Log.i(TAG, "Attempting to configure Wi-Fi. SSID: '$ssid', Identity: '$identity', AnonymousIdentity: '${anonymousIdentity.ifEmpty { "N/A" }}', DomainSuffixMatch: '${domainSuffixMatch.ifEmpty { "N/A" }}'")

        if (ssid.isEmpty()) {
            tvStatus.text = "SSID cannot be empty."
            Log.w(TAG, "Configuration failed: SSID is empty.")
            return
        }
        if (identity.isEmpty()) {
            tvStatus.text = "Identity cannot be empty."
            Log.w(TAG, "Configuration failed: Identity is empty.")
            return
        }
        if (caCertificate == null) {
            tvStatus.text = "CA Certificate not loaded. Please pick a CA certificate."
            Log.w(TAG, "Configuration failed: CA certificate is null.")
            return
        }
        if (clientCertUri == null) {
            tvStatus.text = "Client Certificate P12 (.pfx/.p12) not selected. Please pick one."
            Log.w(TAG, "Configuration failed: Client certificate URI is null.")
            return
        }
        if (clientCertPass.isEmpty()) {
            tvStatus.text = "Client Certificate password cannot be empty."
            Log.w(TAG, "Configuration failed: Client certificate password is empty.")
            return
        }

        // Load client certificate and private key
        if (!loadClientPkcs12(clientCertUri!!, clientCertPass.toCharArray())) {
            // tvStatus is set by loadClientPkcs12 on failure
            Log.w(TAG, "Configuration failed: Could not load client PKCS12.")
            // Clear sensitive data attempt
            clientPrivateKey = null
            clientCertificate = null
            etClientCertPassword.text.clear() // Clear password after attempt
            return
        }
        // Clear password from EditText after attempting to load
        etClientCertPassword.text.clear()


        if (clientPrivateKey == null || clientCertificate == null) {
            tvStatus.text = "Client private key or certificate could not be extracted. Check P12 file and password."
            Log.w(TAG, "Configuration failed: Client private key or certificate is null after load attempt.")
            return
        }

        Log.i(TAG, "CA Certificate loaded: Subject='${caCertificate?.subjectDN?.name}'")
        Log.i(TAG, "Client Certificate loaded: Subject='${clientCertificate?.subjectDN?.name}'")
        Log.i(TAG, "Client Private Key loaded: Algorithm='${clientPrivateKey?.algorithm}'")


        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager

            if (!wifiManager.isWifiEnabled) {
                Log.w(TAG, "Wi-Fi is disabled. Prompting user.")
                AlertDialog.Builder(this)
                    .setTitle("Enable Wi-Fi")
                    .setMessage("Wi-Fi is currently disabled. Please enable it to add this network.")
                    .setPositiveButton("Open Settings") { _, _ ->
                        startActivity(Intent(Settings.Panel.ACTION_WIFI))
                    }
                    .setNegativeButton("Cancel", null)
                    .show()
                tvStatus.text = "Wi-Fi is disabled. Please enable it."
                return
            }

            val enterpriseConfig = WifiEnterpriseConfig().apply {
                eapMethod = WifiEnterpriseConfig.Eap.TLS
                Log.i(TAG, "Setting EAP method to TLS (value: ${WifiEnterpriseConfig.Eap.TLS})")
                this.identity = identity
                Log.i(TAG, "Identity set to: '$identity'")

                if (anonymousIdentity.isNotEmpty()) {
                    this.anonymousIdentity = anonymousIdentity
                    Log.i(TAG, "Anonymous Identity set to: '$anonymousIdentity'")
                } else {
                    Log.i(TAG, "Anonymous Identity not provided.")
                }

                // Set CA certificate
                setCaCertificate(this@MainActivity.caCertificate)
                Log.i(TAG, "CA certificate set in WifiEnterpriseConfig.")

                // Set Client Key and Certificate
                setClientKeyEntryWithCertificateChain(
                    this@MainActivity.clientPrivateKey,
                    arrayOf(this@MainActivity.clientCertificate)
                )
                Log.i(TAG, "Client key and certificate set in WifiEnterpriseConfig.")

                // For domain matching (recommended for security)
                if (domainSuffixMatch.isNotEmpty()) {
                    altSubjectMatch = domainSuffixMatch // Corrected: Removed enterpriseConfig qualifier
                    Log.i(TAG, "Domain Suffix Match (altSubjectMatch) set to: '$domainSuffixMatch'")
                } else {
                    Log.i(TAG, "Domain Suffix Match (altSubjectMatch) not provided.")
                }
            }

            val suggestion = WifiNetworkSuggestion.Builder()
                .setSsid(ssid)
                .setWpa3EnterpriseConfig(enterpriseConfig)
                .setIsAppInteractionRequired(true) // User interaction may be needed to connect
                .build()

            val suggestions = listOf(suggestion)
            val status = wifiManager.addNetworkSuggestions(suggestions)
            val statusText = getNetworkSuggestionStatusText(status)

            when (status) {
                WifiManager.STATUS_NETWORK_SUGGESTIONS_SUCCESS -> {
                    tvStatus.text = "Wi-Fi suggestion for '$ssid' added successfully! Check Wi-Fi settings."
                    Log.i(TAG, "Network suggestion added for '$ssid'. Status: $statusText ($status)")
                    AlertDialog.Builder(this)
                        .setTitle("Network Suggested")
                        .setMessage("The Wi-Fi network '$ssid' has been suggested to the system. You may need to select it from your Wi-Fi list or it might connect automatically if it's the best option.")
                        .setPositiveButton("Open Wi-Fi Settings") { _, _ ->
                            startActivity(Intent(Settings.ACTION_WIFI_SETTINGS))
                        }
                        .setNegativeButton("OK", null)
                        .show()
                }
                else -> {
                    tvStatus.text = "Failed to add Wi-Fi suggestion for '$ssid'. Status: $statusText ($status)"
                    Log.e(TAG, "Failed to add network suggestion for '$ssid'. Status: $statusText ($status)")
                }
            }
        } else {
            tvStatus.text = "This feature requires Android Q (API 29) or higher."
            Log.w(TAG, "API level too low for WifiNetworkSuggestion.")
        }
        // Clear sensitive data after configuration attempt
        clientPrivateKey = null
        // clientCertificate is fine to keep if needed for display, but private key is critical
    }

    private fun getNetworkSuggestionStatusText(status: Int): String {
        return when (status) {
            WifiManager.STATUS_NETWORK_SUGGESTIONS_SUCCESS -> "SUCCESS"
            WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_DUPLICATE -> "ERROR_ADD_DUPLICATE"
            WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_EXCEEDS_MAX_PER_APP -> "ERROR_ADD_EXCEEDS_MAX_PER_APP"
            WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_APP_DISALLOWED -> "ERROR_APP_DISALLOWED"
            WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_INTERNAL -> "ERROR_INTERNAL"
            WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID -> "ERROR_REMOVE_INVALID"
            // Add any other specific codes if new ones are introduced in future Android versions
            else -> "UNKNOWN_STATUS_CODE"
        }
    }
}
