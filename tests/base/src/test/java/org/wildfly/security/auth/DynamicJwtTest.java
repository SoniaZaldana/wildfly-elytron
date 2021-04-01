/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
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
package org.wildfly.security.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.wildfly.common.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.x500.X500Principal;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslServer;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.ClientUtils;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.auth.server.jwt.JwtUtils;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.ModifiableSecurityRealm;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.auth.server.jwt.TokenConfiguration;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.sasl.SaslMechanismSelector;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.plain.PlainSaslServerFactory;
import org.wildfly.security.sasl.plain.WildFlyElytronSaslPlainProvider;
import org.wildfly.security.sasl.test.SaslServerBuilder;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;


/**
 * Tests to verify functionality available in JwtUtils, as well as
 * ensuring tokens get created and added as a private identity throughout the
 * authentication process.
 *
 * @author <a href="mailto:szaldana@redhat.com">Sonia Zaldana</a>
 */
public class DynamicJwtTest {

    private final String USER = "Sonia";
    private final String PASSWORD = "secretPassword";
    private final String REALM_NAME = "default";
    private final String ISSUER = "WildFly Elytron";
    private final String AUDIENCE = "JWT";
    private static final String PLAIN = "PLAIN";


    private static final Provider[] providers = new Provider[] {
            WildFlyElytronSaslPlainProvider.getInstance(),
            WildFlyElytronPasswordProvider.getInstance()
    };

    @BeforeClass
    public static void onBefore()  {
        Security.addProvider(providers[0]);
        Security.addProvider(providers[1]);
    }

    @AfterClass
    public static void onAfter() {
        Security.removeProvider(providers[0].getName());
        Security.removeProvider(providers[1].getName());
    }

    /**
     *  Tests using a security identity and default token configuration
     *  to issue JWT tokens. Then, verifies the token and its contents.
     */
    @Test
    public void testIssuingTokenWithJwtUtilsDefaultConfig() throws Exception {
        FileSystemSecurityRealm fileSystemSecurityRealm = createSecurityRealm();

        // Default token configuration
        TokenConfiguration tokenConfig = TokenConfiguration.builder()
                .build();

        SecurityDomain domain = SecurityDomain.builder().setDefaultRealmName(REALM_NAME).addRealm(REALM_NAME, fileSystemSecurityRealm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .setTokenConfiguration(tokenConfig)
                .build();
        ServerAuthenticationContext sac1 = domain.createNewAuthenticationContext();

        sac1.setAuthenticationName(USER);
        assertTrue(sac1.verifyEvidence(new PasswordGuessEvidence(PASSWORD.toCharArray())));
        assertTrue(sac1.authorize());
        sac1.succeed();

        // Fetch security identity to test issuing the token
        SecurityIdentity identity = sac1.getAuthorizedIdentity();
        String jwtToken = JwtUtils.issueJwtToken(identity, domain.getTokenConfiguration());
        assertNotNull(jwtToken);

        // Validate the contents of the JWT is what we configured
        JsonWebToken jwt = JwtUtils.parseAndVerifyToken(jwtToken, domain.getTokenConfiguration());
        assertNotNull(jwt);
        assertEquals(jwt.getIssuer(), ISSUER);
        assertEquals(jwt.getSubject(), USER);
        assertEquals(jwt.getAudience(), new HashSet<>(Arrays.asList(AUDIENCE)));
        assertEquals(jwt.getGroups(), new HashSet<>(Arrays.asList("Employee", "Admin", "Manager")));

        deleteKeyStore(tokenConfig.getKeyStorePath());
    }


    /**
     *  Tests using a security identity and a custom token configuration
     *  to issue JWT tokens. In this example, we assume user already has configured
     *  a keystore they want to use, so we specify where this keystore is located along
     *  with the required aliases and password.
     */
    @Test
    public void testIssuingTokenWithJwtUtilsCustomConfig() throws Exception {
        FileSystemSecurityRealm fileSystemSecurityRealm = createSecurityRealm();

        generateUserKeyStore("myKeystore.jks", "mySigningAlias", "myEncryptionAlias", "mySecret");

        // Custom token configuration
        TokenConfiguration tokenConfig = TokenConfiguration.builder()
                .setEncryptionAlias("myEncryptionAlias")
                .setSigningAlias("mySigningAlias")
                .setKeyStorePassword("mySecret")
                .setKeyStorePath(Paths.get("myKeystore.jks"))
                .setExpiryTime(400)
                .setIssuer("Some Issuer")
                .setAudience(new HashSet<>(Arrays.asList("JWT1", "JWT2")))
                .setKeySize(4096)
                .build();

        SecurityDomain domain = SecurityDomain.builder().setDefaultRealmName(REALM_NAME).addRealm(REALM_NAME, fileSystemSecurityRealm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .setTokenConfiguration(tokenConfig)
                .build();
        ServerAuthenticationContext sac1 = domain.createNewAuthenticationContext();

        sac1.setAuthenticationName(USER);
        assertTrue(sac1.verifyEvidence(new PasswordGuessEvidence(PASSWORD.toCharArray())));
        assertTrue(sac1.authorize());
        sac1.succeed();

        // Fetch security identity to test issuing the token
        SecurityIdentity identity = sac1.getAuthorizedIdentity();
        String jwtToken = JwtUtils.issueJwtToken(identity, domain.getTokenConfiguration());
        assertNotNull(jwtToken);

        // Validate the contents of the JWT is what we configured
        JsonWebToken jwt = JwtUtils.parseAndVerifyToken(jwtToken, domain.getTokenConfiguration());
        assertNotNull(jwt);
        assertEquals(jwt.getIssuer(), "Some Issuer");
        assertEquals(jwt.getSubject(), "Sonia");
        assertEquals(jwt.getAudience(), new HashSet<>(Arrays.asList("JWT1", "JWT2")));
        assertEquals(jwt.getGroups(), new HashSet<>(Arrays.asList("Employee", "Admin", "Manager")));

        deleteKeyStore(tokenConfig.getKeyStorePath());
    }

    @Test
    public void testSuccessfulIssuingTokenAndAdddingAsPrivateCredential() throws Exception {

        TokenConfiguration tokenConfiguration = TokenConfiguration.builder().build();
        SaslServer server = createSaslServer(USER, PASSWORD.toCharArray(), tokenConfiguration);

        CallbackHandler clientCallback = createClientCallbackHandler(USER, PASSWORD.toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[]{PLAIN}, USER, "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        Assert.assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);
        assertEquals("Sonia\0Sonia\0secretPassword",new String(message, StandardCharsets.UTF_8));

        server.evaluateResponse(message);
        Assert.assertTrue(server.isComplete());
        Assert.assertTrue(client.isComplete());
        assertEquals(USER, server.getAuthorizationID());

        // Verify the generated token is now a private credential for the security identity
        SecurityIdentity securityIdentity = (SecurityIdentity) server.getNegotiatedProperty(WildFlySasl.SECURITY_IDENTITY);
        IdentityCredentials credentials = securityIdentity.getPrivateCredentials();

        assertNotNull(credentials);
        assertTrue(credentials.size() == 2); // Includes password credential and bearer token credential
        assertNotNull(credentials.getCredential(BearerTokenCredential.class));

        String generatedJwt = credentials.getCredential(BearerTokenCredential.class).getToken();

        // Validate the contents of the JWT is what we configured
        JsonWebToken jwt = JwtUtils.parseAndVerifyToken(generatedJwt, tokenConfiguration);
        assertNotNull(jwt);
        assertEquals(jwt.getIssuer(), ISSUER);
        assertEquals(jwt.getSubject(), USER);
        assertEquals(jwt.getAudience(), new HashSet<>(Arrays.asList(AUDIENCE)));
        assertEquals(jwt.getGroups(), new HashSet<>(Arrays.asList("Employee", "Admin", "Manager")));


        deleteKeyStore(tokenConfiguration.getKeyStorePath());
    }

    private void generateUserKeyStore(String keystoreLocation, String signingAlias, String encryptionAlias, String password) throws Exception {
        File file = Paths.get(keystoreLocation).toFile();
        KeyStore keyStore = KeyStore.getInstance("JKS");
        // Create Signing KeyPair
        SelfSignedX509CertificateAndSigningKey certificateSigning =
                generateCertificate("cn=UserSigning");

        // Create Encryption Keypair
        SelfSignedX509CertificateAndSigningKey certificateEncryption =
                generateCertificate("cn=UserEncryption");

        X509Certificate[] certificateChainSigning = {certificateSigning.getSelfSignedCertificate()};
        X509Certificate[] certificateChainEncryption = {certificateEncryption.getSelfSignedCertificate()};

        // Set keystore entries
        keyStore.load(null, null);
        keyStore.setKeyEntry(signingAlias, certificateSigning.getSigningKey(), password.toCharArray(), certificateChainSigning);
        keyStore.setKeyEntry(encryptionAlias, certificateEncryption.getSigningKey(), password.toCharArray(), certificateChainEncryption);
        keyStore.store(new FileOutputStream(file), password.toCharArray());
    }

    private SelfSignedX509CertificateAndSigningKey generateCertificate(String dn) {
        return SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(new X500Principal(dn))
                .setKeySize(4096)
                .setKeyAlgorithmName("RSA")
                .build();
    }

    private CallbackHandler createClientCallbackHandler(final String username, final char[] password) throws Exception {
        final AuthenticationContext context = AuthenticationContext.empty()
                .with(
                        MatchRule.ALL,
                        AuthenticationConfiguration.empty()
                                .useName(username)
                                .usePassword(password)
                                .setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism(PLAIN)));


        return ClientUtils.getCallbackHandler(new URI("doesnot://matter?"), context);
    }

    private SaslServer createSaslServer(final String expectedUsername, final char[] expectedPassword, TokenConfiguration tokenConfig) throws Exception {
        MapAttributes attributes = new MapAttributes();
        attributes.addAll("Roles", Arrays.asList("Employee", "Manager", "Admin"));

        return new SaslServerBuilder(PlainSaslServerFactory.class, PLAIN)
                .setProviderSupplier(() -> providers)
                .setTokenConfiguration(tokenConfig)
                .setUserName(expectedUsername)
                .setPassword(expectedPassword)
                .setModifiableRealm()
                .setAttributes(attributes)
                .build();
    }

    private void deleteKeyStore(Path path) {
        File file = path.toFile();
        if (file.exists()) {
            file.delete();
        }
    }

    private FileSystemSecurityRealm createSecurityRealm() throws Exception {
        FileSystemSecurityRealm realm = new FileSystemSecurityRealm(getRootPath(true));
        char[] password = PASSWORD.toCharArray();
        PasswordFactory factory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        ClearPassword clearPassword = (ClearPassword) factory.generatePassword(new ClearPasswordSpec(password));
        addUser(realm, USER, clearPassword);
        return realm;
    }

    private Path getRootPath(boolean deleteIfExists) throws Exception {
        Path rootPath = Paths.get(getClass().getResource(File.separator).toURI())
                .resolve("filesystem-realm");

        if (rootPath.toFile().exists() && !deleteIfExists) {
            return rootPath;
        }

        return Files.walkFileTree(Files.createDirectories(rootPath), new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private void addUser(ModifiableSecurityRealm realm, String userName, Password credential) throws RealmUnavailableException {
        ModifiableRealmIdentity realmIdentity = realm.getRealmIdentityForUpdate(new NamePrincipal(userName));
        realmIdentity.create();
        realmIdentity.setCredentials(Collections.singleton(new PasswordCredential(credential)));
        MapAttributes attributes = new MapAttributes();
        attributes.addAll("Roles", Arrays.asList("Employee", "Manager", "Admin"));
        realmIdentity.setAttributes(attributes);
        realmIdentity.dispose();

    }

}
