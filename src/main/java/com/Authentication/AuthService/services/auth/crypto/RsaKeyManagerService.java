package com.Authentication.AuthService.services.auth.crypto;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class RsaKeyManagerService implements RsaKeyProvider {
    private final FileKeyStore fileKeyStore;
    private final PemKeyParse pemKeyParse;
    private final RsaKeyGenerator rsaKeyGenerator;
    private final KeyIdGenerator keyIdGenerator;
    private final ResourceLoader resourceLoader;

    @Value("${jwt.rsa.private-key-path}")
    private String privateKeyPath;

    @Value("${jwt.rsa.public-key-path}")
    private String publicKeyPath;

    @Value("${jwt.rsa.key-size}")
    private int keySize;

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private String keyId;

    @PostConstruct
    void initialize() throws IOException {
        Resource privatResource = resourceLoader.getResource(privateKeyPath);
        Resource publicResource = resourceLoader.getResource(publicKeyPath);

        File privateFile = privatResource.getFile();
        File publicFile = publicResource.getFile();

        var privateKeyBytes = fileKeyStore.read(privateFile);
        var publicKeyBytes = fileKeyStore.read(publicFile);

        if (privateKeyBytes.isPresent() && publicKeyBytes.isPresent()) {
            log.info("Loading RSA keys from files");
            this.privateKey = pemKeyParse.parsePrivateKey(privateKeyBytes.get());
            this.publicKey = pemKeyParse.parsePublicKey(publicKeyBytes.get());
        } else {
            log.warn("RSA keys not found, generating new ones");
            KeyPair keyPair = rsaKeyGenerator.generate(keySize);
            this.privateKey = keyPair.getPrivate();
            this.publicKey = keyPair.getPublic();

            fileKeyStore.write(privateFile, CryptoContants.PEM_PRIVATE_HEADER, privateKey.getEncoded(),
                    CryptoContants.PEM_PRIVATE_FOOTER);

            fileKeyStore.write(publicFile, CryptoContants.PEM_PUBLIC_HEADER, publicKey.getEncoded(),
                    CryptoContants.PEM_PUBLIC_FOOTER);
        }

        this.keyId = keyIdGenerator.generate(publicKey);
        log.info("RSA initialized with kid={}", keyId);
    }

    @Override
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public String getKeyId() {
        return keyId;
    }
}
