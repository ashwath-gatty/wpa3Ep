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
        return try {
            val certificateFactory = CertificateFactory.getInstance("X.509")
            certificateFactory.generateCertificate(inputStream) as X509Certificate
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse X.509 certificate", e)
            null
        }
    }

    private fun loadClientPkcs12(uri: Uri, password: CharArray): Boolean {
        return try {
            contentResolver.openInputStream(uri)?.use { inputStream ->
                val keyStore = KeyStore.getInstance("PKCS12")
                keyStore.load(inputStream, password)
                val aliases = keyStore.aliases()
                if (aliases.hasMoreElements()) {
                    val alias = aliases.nextElement()
                    clientPrivateKey = keyStore.getKey(alias, password) as? PrivateKey
                    clientCertificate = keyStore.getCertificate(alias) as? X509Certificate

                    if (clientPrivateKey != null && clientCertificate != null) {
                        Log.i(TAG, "Client PKCS12 loaded successfully. Alias: $alias")
                        return true
                    } else {
                        Log.e(TAG, "Failed to extract key/certificate from PKCS12. Alias: $alias")
                        if (clientPrivateKey == null) Log.e(TAG, "Private key is null")
                        if (clientCertificate == null) Log.e(TAG, "Client certificate is null") else TODO()
                    }
                } else {
                    Log.e(TAG, "No aliases found in PKCS12 keystore.")
                }
            }
            false
        } catch (e: Exception) {
            Log.e(TAG, "Error loading PKCS12 client certificate", e)
            tvStatus.text = "Error loading client cert: ${e.message}"
            false
        }
    }


    @SuppressLint("MissingPermission") // Permissions are checked before calling
    private fun configureWifi() {
        val ssid = etSsid.text.toString().trim()
        val identity = etIdentity.text.toString().trim()
        val clientCertPass = etClientCertPassword.text.toString() // DO NOT log this in production

        if (ssid.isEmpty()) {
            tvStatus.text = "SSID cannot be empty."
            return
        }
        if (identity.isEmpty()) {
            tvStatus.text = "Identity cannot be empty."
            return
        }
        if (caCertificate == null) {
            tvStatus.text = "CA Certificate not loaded."
            return
        }
        if (clientCertUri == null) {
            tvStatus.text = "Client Certificate (.pfx) not selected."
            return
        }
        if (clientCertPass.isEmpty()) {
            // In a real app, prompt more securely or handle this better
            tvStatus.text = "Client Certificate password cannot be empty."
            return
        }

        // Load client certificate and private key
        if (!loadClientPkcs12(clientCertUri!!, clientCertPass.toCharArray())) {
            tvStatus.text = "Failed to load client certificate. Check password or file."
            // Clear sensitive data attempt
            clientPrivateKey = null
            clientCertificate = null
            etClientCertPassword.text.clear() // Clear password after attempt
            return
        }
        // Clear password from EditText after attempting to load
        etClientCertPassword.text.clear()


        if (clientPrivateKey == null || clientCertificate == null) {
            tvStatus.text = "Client private key or certificate is missing after load attempt."
            return
        }


        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager

            if (!wifiManager.isWifiEnabled) {
                // Prompt user to enable Wi-Fi
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
                eapMethod = WifiEnterpriseConfig.Eap.TLS // EAP-TLS
                this.identity = identity
                // Anonymous identity can be set if required by the network
                // anonymousIdentity = "anonymous@example.com"

                // Set CA certificate
                // For multiple CAs, you might need to bundle them or use system trust store if applicable
                setCaCertificate(this@MainActivity.caCertificate)

                // Set Client Key and Certificate
                // IMPORTANT: This handles the private key. Ensure it's done securely.
                setClientKeyEntryWithCertificateChain(
                    this@MainActivity.clientPrivateKey,
                    arrayOf(this@MainActivity.clientCertificate) // Chain might include intermediate CAs
                )
                // For domain matching (recommended for security)
                // altSubjectMatch = "DNS:yourserver.example.com" // Replace with your server's domain
            }

            val suggestion = WifiNetworkSuggestion.Builder()
                .setSsid(ssid)
                .setWpa3EnterpriseConfig(enterpriseConfig)
                .setIsAppInteractionRequired(true) // User interaction may be needed to connect
                .build()

            val suggestions = listOf(suggestion)
            val status = wifiManager.addNetworkSuggestions(suggestions)

            when (status) {
                WifiManager.STATUS_NETWORK_SUGGESTIONS_SUCCESS -> {
                    tvStatus.text = "Wi-Fi suggestion for '$ssid' added successfully! Check Wi-Fi settings."
                    Log.i(TAG, "Network suggestion added for $ssid")
                    // Prompt user to connect or check Wi-Fi settings
                    AlertDialog.Builder(this)
                        .setTitle("Network Suggested")
                        .setMessage("The Wi-Fi network '$ssid' has been suggested to the system. You may need to select it from your Wi-Fi list or it might connect automatically if it's the best option.")
                        .setPositiveButton("Open Wi-Fi Settings") { _, _ ->
                            startActivity(Intent(Settings.ACTION_WIFI_SETTINGS))
                        }
                        .setNegativeButton("OK", null)
                        .show()
                }
                WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_DUPLICATE -> {
                    tvStatus.text = "Error: Suggestion for '$ssid' already exists."
                    Log.w(TAG, "Duplicate network suggestion for $ssid")
                }
                WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_EXCEEDS_MAX_PER_APP -> {
                    tvStatus.text = "Error: Exceeded max suggestions per app."
                    Log.w(TAG, "Exceeded max suggestions")
                }
                WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_APP_DISALLOWED -> {
                    tvStatus.text = "Error: App is disallowed from making suggestions. Check app permissions or restrictions."
                    Log.e(TAG, "App disallowed from making suggestions")
                }
                WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_INTERNAL -> {
                    tvStatus.text = "Error: Internal error adding suggestion for '$ssid'."
                    Log.e(TAG, "Internal error adding suggestion for $ssid")
                }
                WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID -> {
                    tvStatus.text = "Error: Invalid suggestion to remove (should not happen here)."
                    Log.e(TAG, "Error remove invalid (unexpected).")
                }
                else -> {
                    tvStatus.text = "Failed to add Wi-Fi suggestion for '$ssid'. Status code: $status"
                    Log.e(TAG, "Failed to add network suggestion for $ssid, status: $status")
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
}
