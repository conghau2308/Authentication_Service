package com.Authentication.AuthService.services.auth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
@Slf4j
public class RsaKeyService {

    @Value("${jwt.rsa.private-key-path:keys/private_key.pem}")
    private String privateKeyPath;

    @Value("${jwt.rsa.public-key-path:keys/public_key.pem}")
    private String publicKeyPath;

    @Value("${jwt.rsa.key-size:2048}")
    private int keySize;

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private String keyId; // Key ID cho JWKS

    @PostConstruct
    public void init() {
        try {
            loadOrGenerateKeys();
            this.keyId = generateKeyId();
            log.info("✅ RSA Keys initialized successfully with Key ID: {}", keyId);
        } catch (Exception e) {
            log.error("❌ Failed to initialize RSA keys", e);
            throw new RuntimeException("Cannot initialize RSA keys", e);
        }
    }

    /**
     * Load keys từ file hoặc generate mới nếu chưa có
     */
    private void loadOrGenerateKeys() throws Exception {
        File privateKeyFile = new File(privateKeyPath);
        File publicKeyFile = new File(publicKeyPath);

        if (privateKeyFile.exists() && publicKeyFile.exists()) {
            log.info("Loading existing RSA keys from files...");
            this.privateKey = loadPrivateKey(privateKeyFile);
            this.publicKey = loadPublicKey(publicKeyFile);
        } else {
            log.info("Generating new RSA key pair...");
            KeyPair keyPair = generateKeyPair();
            this.privateKey = keyPair.getPrivate();
            this.publicKey = keyPair.getPublic();

            // Save keys to files
            saveKeys(privateKeyFile, publicKeyFile);
        }
    }

    /**
     * Generate RSA key pair
     */
    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Load private key từ file
     */
    private PrivateKey loadPrivateKey(File file) throws Exception {
        byte[] keyBytes = readKeyFile(file);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    /**
     * Load public key từ file
     */
    private PublicKey loadPublicKey(File file) throws Exception {
        byte[] keyBytes = readKeyFile(file);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    /**
     * Đọc key file và decode Base64
     */
    private byte[] readKeyFile(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            String keyContent = new String(fis.readAllBytes())
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            return Base64.getDecoder().decode(keyContent);
        }
    }

    /**
     * Save keys to files
     */
    private void saveKeys(File privateKeyFile, File publicKeyFile) throws IOException {
        // Create directories if not exist
        privateKeyFile.getParentFile().mkdirs();
        publicKeyFile.getParentFile().mkdirs();

        // Save private key
        try (FileOutputStream fos = new FileOutputStream(privateKeyFile)) {
            String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
                    Base64.getEncoder().encodeToString(privateKey.getEncoded()) + "\n" +
                    "-----END PRIVATE KEY-----\n";
            fos.write(privateKeyPem.getBytes());
        }

        // Save public key
        try (FileOutputStream fos = new FileOutputStream(publicKeyFile)) {
            String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
                    Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n" +
                    "-----END PUBLIC KEY-----\n";
            fos.write(publicKeyPem.getBytes());
        }

        log.info("✅ RSA keys saved to files");
    }

    /**
     * Generate unique Key ID (kid) cho JWKS
     */
    private String generateKeyId() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(publicKey.getEncoded());
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(hash).substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            return "default-key-id";
        }
    }

    // Getters
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getKeyId() {
        return keyId;
    }

    /**
     * Get public key in Base64 format (cho JWKS endpoint)
     */
    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
}