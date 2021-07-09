/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
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

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.spec.Encoding;
import org.wildfly.security.encryption.SecretKeyUtil;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import javax.crypto.SecretKey;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
// has dependency on wildfly-elytron-realm, wildfly-elytron-auth-server, wildfly-elytron-credential
public class FileSystemSecurityRealmTest {

    private static final Provider provider = WildFlyElytronPasswordProvider.getInstance();
    SecretKey key = SecretKeyUtil.generateSecretKey(128);

    public FileSystemSecurityRealmTest() throws GeneralSecurityException {
    }

    @BeforeClass
    public static void onBefore() throws Exception {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void onAfter() throws Exception {
        Security.removeProvider(provider.getName());
    }

    @Test
    public void testCreateIdentityWithNoLevels() throws Exception {

        FileSystemSecurityRealm securityRealm = new FileSystemSecurityRealm(getRootPath(), 0, key);
        ModifiableRealmIdentity identity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));

        assertFalse(identity.exists());

        identity.create();

        assertTrue(identity.exists());
    }

    private void assertCreateIdentityWithPassword(char[] actualPassword, Password credential) throws Exception {
        assertCreateIdentityWithPassword(actualPassword, credential, Encoding.BASE64, StandardCharsets.UTF_8);
    }

    private void assertCreateIdentityWithPassword(char[] actualPassword, Password credential, Encoding hashEncoding, Charset hashCharset) throws Exception {
        FileSystemSecurityRealm securityRealm = new FileSystemSecurityRealm(getRootPath(), 1, hashEncoding, hashCharset, key);
        ModifiableRealmIdentity newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        newIdentity.create();
        newIdentity.setCredentials(Collections.singleton(new PasswordCredential(credential)));
        newIdentity.dispose();

        securityRealm = new FileSystemSecurityRealm(getRootPath(false), 1, hashEncoding, hashCharset, key);
        ModifiableRealmIdentity existingIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        assertTrue(existingIdentity.exists());
        assertTrue(existingIdentity.verifyEvidence(new PasswordGuessEvidence(actualPassword)));
        existingIdentity.dispose();
    }

    private static byte[] generateRandomSalt(int saltSize) {
        byte[] randomSalt = new byte[saltSize];
        ThreadLocalRandom.current().nextBytes(randomSalt);
        return randomSalt;
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

    private Path getRootPath() throws Exception {
        return getRootPath(true);
    }

}
