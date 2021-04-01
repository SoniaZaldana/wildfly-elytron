/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2021 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.auth.server.jwt;

import static org.wildfly.security.auth.server._private.ElytronMessages.log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.wildfly.common.Assert;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;

/**
 * A token configuration class which holds information regarding dynamic token issuance
 * including encryption and signing keys. This configuration is mapped to a {@link SecurityDomain}
 * to use for all tokens generated during the authentication process associated with this Security Domain.
 *
 * @author <a href="mailto:szaldana@redhat.com">Sonia Zaldana</a>
 */
public class TokenConfiguration {

    private KeyStore keyStore;
    private String issuer = "WildFly Elytron";
    private long expiryTime = 300;
    private List<String> audience = Arrays.asList("JWT");
    private String keyStorePassword = "secret";
    private String signingAlias = "serverSigning";
    private String encryptionAlias = "serverEncryption";
    private Path keyStorePath = Paths.get("tokenKeystore.jks");
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;
    private KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.RSA_OAEP_256;
    private int keySize = 2048;
    private PublicKey encryptionKey;
    private PrivateKey decryptionKey;
    private PublicKey verificationKey;
    private PrivateKey signingKey;

    private final String SIGNING_DN = "cn=WildFly Elytron Signing";
    private final String ENCRYPTION_DN = "cn=WildFly Elytron Encryption";


    public TokenConfiguration(Builder builder) throws Exception {
        if (builder.issuer != null) {
            this.issuer = builder.issuer;
        }
        if (builder.expiryTime != 0) {
            this.expiryTime = builder.expiryTime;
        }
        if (builder.audience != null) {
            this.audience = builder.audience;
        }
        if (builder.keyStorePassword != null) {
            this.keyStorePassword = builder.keyStorePassword;
        }
        if (builder.keyEncryptionAlgorithm != null) {
            this.keyEncryptionAlgorithm = builder.keyEncryptionAlgorithm;
        }
        if (builder.signatureAlgorithm != null) {
            this.signatureAlgorithm = builder.signatureAlgorithm;
        }
        if (builder.keySize != 0) {
            this.keySize = builder.keySize;
        }

        // User provided keystore, store its path and respective aliases
        if (builder.keyStorePath != null) {
            this.keyStorePath = builder.keyStorePath;
            this.keyStorePassword = builder.keyStorePassword;
            this.encryptionAlias = builder.encryptionAlias;
            this.signingAlias = builder.signingAlias;
        }

        // Store keystore along with encryption and signing key pairs.
        this.keyStore = loadKeyStore(this.keyStorePath, this.keyStorePassword);

        try {
            this.encryptionKey = loadPublicKey(this.keyStore, this.encryptionAlias);
            this.decryptionKey = loadPrivateKey(this.keyStore, this.encryptionAlias, this.keyStorePassword);
            this.signingKey = loadPrivateKey(this.keyStore, this.signingAlias, this.keyStorePassword);
            this.verificationKey = loadPublicKey(this.keyStore, this.signingAlias);
        } catch (Exception e) {
            throw log.failedToLoadKey(e);
        }

    }

    public String getSigningAlias() {
        return this.signingAlias;
    }

    public String getEncryptionAlias() {
        return this.encryptionAlias;
    }

    public Path getKeyStorePath() {
        return this.keyStorePath;
    }

    public String getKeyStorePassword() {
        return this.keyStorePassword;
    }

    public String getIssuer() {
        return this.issuer;
    }

    public List<String> getAudience() {
        return this.audience;
    }

    public long getExpiryTime() {
        return this.expiryTime;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return this.signatureAlgorithm;
    }

    public KeyEncryptionAlgorithm getKeyEncryptionAlgorithm() {
        return this.keyEncryptionAlgorithm;
    }

    public PublicKey getEncryptionKey() {
        return this.encryptionKey;
    }

    public PrivateKey getDecryptionKey() {
        return this.decryptionKey;
    }

    public PublicKey getVerificationKey() {
        return this.verificationKey;
    }

    public PrivateKey getSigningKey() {
        return this.signingKey;
    }

    private KeyStore loadKeyStore(Path keyStorePath, String password) throws Exception {
        File file = keyStorePath.toFile();
        KeyStore keyStore = KeyStore.getInstance("JKS");
        if (file.exists()) {
            // if exists, load
            try {
                keyStore.load(new FileInputStream(file), password.toCharArray());
            } catch (Exception e) {
                throw log.keystoreFileDoesNotExist(e);
            }
        } else {
            // Create Signing KeyPair
            SelfSignedX509CertificateAndSigningKey certificateSigning =
                    generateCertificate(SIGNING_DN);

            // Create Encryption Keypair
            SelfSignedX509CertificateAndSigningKey certificateEncryption =
                    generateCertificate(ENCRYPTION_DN);

            X509Certificate[] certificateChainSigning = {certificateSigning.getSelfSignedCertificate()};
            X509Certificate[] certificateChainEncryption = {certificateEncryption.getSelfSignedCertificate()};

            // Set keystore entries
            try {
                keyStore.load(null, null);
                keyStore.setKeyEntry(this.signingAlias, certificateSigning.getSigningKey(), password.toCharArray(), certificateChainSigning);
                keyStore.setKeyEntry(this.encryptionAlias, certificateEncryption.getSigningKey(), password.toCharArray(), certificateChainEncryption);
                keyStore.store(new FileOutputStream(file), password.toCharArray());
            } catch (NoSuchAlgorithmException e) {
                throw log.noSuchAlgorithmToCheckKeyStoreIntegrity(e);
            } catch (CertificateException e) {
                throw log.couldNotStoreCertificate(e);
            }

        }
        return keyStore;
    }

    private SelfSignedX509CertificateAndSigningKey generateCertificate(String dn) {
        return SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(new X500Principal(dn))
                .setKeySize(this.keySize)
                .setKeyAlgorithmName("RSA")
                .build();
    }

    private PrivateKey loadPrivateKey(KeyStore keyStore, String alias, String password) throws Exception {
        return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
    }

    private PublicKey loadPublicKey(KeyStore keyStore, String alias) throws Exception {
        return keyStore.getCertificate(alias).getPublicKey();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String signingAlias;
        private String encryptionAlias;
        private Path keyStorePath;
        private String keyStorePassword;
        private String issuer;
        private List<String> audience;
        private long expiryTime;
        private SignatureAlgorithm signatureAlgorithm;
        private KeyEncryptionAlgorithm keyEncryptionAlgorithm;
        private int keySize;


        Builder() {

        }

        /**
         * Set the alias associated with the signing keypair entry in the keystore
         * @param signingAlias the alias for the signing keypair
         * @return this builder
         */
        public Builder setSigningAlias(String signingAlias) {
            Assert.assertNotNull(signingAlias);
            this.signingAlias = signingAlias;
            return this;
        }

        /**
         * Set the alias associated with the encryption keypair entry in the keystore
         * @param encryptionAlias the alias for the encryption keypair
         * @return this builder
         */
        public Builder setEncryptionAlias(String encryptionAlias) {
            Assert.assertNotNull(encryptionAlias);
            this.encryptionAlias = encryptionAlias;
            return this;
        }

        /**
         * Set the path where the is stored
         * @param path the path to the keystore
         * @return this builder
         */
        public Builder setKeyStorePath(Path path) {
            Assert.assertNotNull(path);
            this.keyStorePath = path;
            return this;
        }

        /**
         * Set the clear text password to use with the keystore
         * @param password the password
         * @return this builder
         */
        // TODO look into whether this should be a different type. Maybe ClearPassword?
        public Builder setKeyStorePassword(String password) {
            Assert.assertNotNull(password);
            this.keyStorePassword = password;
            return this;
        }

        /**
         * Set the value for the issuer claim
         * @param issuer the issuer
         * @return this builder
         */
        public Builder setIssuer(String issuer) {
            Assert.assertNotNull(issuer);
            this.issuer = issuer;
            return this;
        }

        /**
         * Set the value for the audience claim
         * @param audience the intended audience
         * @return this builder
         */
        public Builder setAudience(String audience) {
            Assert.assertNotNull(audience);
            this.audience = Arrays.asList(audience);
            return this;
        }

        public Builder setAudience(Set<String> audience) {
            Assert.assertNotNull(audience);
            this.audience = new ArrayList<>(audience);
            return this;
        }

        /**
         * Set the token's expiry time in seconds
         * @param expiryTime the expiry time
         * @return this builder
         */
        public Builder setExpiryTime(long expiryTime) {
            Assert.assertNotNull(expiryTime);
            this.expiryTime = expiryTime;
            return this;
        }

        /**
         * Set the signature algorithm to use during the token issuance
         * @param signatureAlgorithm the signature algorithm
         * @return this builder
         */
        public Builder setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
            Assert.assertNotNull(signatureAlgorithm);
            this.signatureAlgorithm = signatureAlgorithm;
            return this;
        }

        /**
         * Set the encryption algorithm to use during the token issuance
         * @param keyEncryptionAlgorithm the encryption algorithm
         * @return this builder
         */
        public Builder setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm keyEncryptionAlgorithm) {
            Assert.assertNotNull(keyEncryptionAlgorithm);
            this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
            return this;
        }

        /**
         * Set the key size for the automatically generated keys
         * @param keySize the key size
         * @return this builder
         */
        public Builder setKeySize(int keySize) {
            Assert.assertNotNull(keySize);
            this.keySize = keySize;
            return this;
        }

        public TokenConfiguration build() throws Exception {
            return new TokenConfiguration(this);
        }
    }
}
