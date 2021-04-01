/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.server.jwt;

import static org.wildfly.security.auth.server._private.ElytronMessages.log;

import java.util.HashSet;
import java.util.List;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.lang.JoseException;
import org.wildfly.common.Assert;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server._private.ElytronMessages;
import org.wildfly.security.authz.Roles;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;


/**
 * A utility class to dynamically issue and parse JWT tokens.
 *
 * @author <a href="mailto:szaldana@redhat.com">Sonia Zaldana</a>
 */
public class JwtUtils {

    /**
     * Dynamically issues a JsonWebToken by using the information available in the tokenConfiguration object
     * and the securityIdentity.
     *
     * @param securityIdentity the security identity to create the token for
     * @param tokenConfiguration tokenConfiguration contains information pertaining token contents and keys.
     * @return a JWT token
     */
    public static String issueJwtToken(SecurityIdentity securityIdentity, TokenConfiguration tokenConfiguration) throws Exception {
        Assert.assertNotNull(securityIdentity);
        Assert.assertNotNull(tokenConfiguration);

        Roles roles = securityIdentity.getRoles();
        HashSet<String> groups = new HashSet<>();
        roles.spliterator().forEachRemaining(role -> groups.add(role));

        JwtClaimsBuilder  builder = Jwt.claims();
        builder.groups(groups)
                .issuer(tokenConfiguration.getIssuer())
                .subject(securityIdentity.getPrincipal().getName())
                .audience(new HashSet<>(tokenConfiguration.getAudience()))
                .expiresIn(tokenConfiguration.getExpiryTime());

        if (tokenConfiguration.getSigningKey() != null && tokenConfiguration.getSignatureAlgorithm() != null) {
            if (tokenConfiguration.getEncryptionKey() != null && tokenConfiguration.getKeyEncryptionAlgorithm() != null) {
                // We inner sign and encrypt
                return builder.jws().algorithm(tokenConfiguration.getSignatureAlgorithm())
                        .innerSign(tokenConfiguration.getSigningKey())
                        .keyAlgorithm(tokenConfiguration.getKeyEncryptionAlgorithm())
                        .encrypt(tokenConfiguration.getEncryptionKey());
            } else {
                // We just sign
                return builder.jws().algorithm(tokenConfiguration.getSignatureAlgorithm())
                        .sign(tokenConfiguration.getSigningKey());
            }
        }
        throw ElytronMessages.log.missingKeysToIssueJwt();
    }

    /**
     * Parse and verify JWT token.
     * @param token the JWT token
     * @param tokenConfiguration tokenConfiguration contains information pertaining token contents and keys.
     * @return a JwtContext object
     */
    public static JsonWebToken parseAndVerifyToken(final String token, final TokenConfiguration tokenConfiguration) throws Exception {
        Assert.assertNotNull(token);
        Assert.assertNotNull(tokenConfiguration);

        String tokenSequence = token;
        if (tokenConfiguration.getDecryptionKey() != null && tokenConfiguration.getKeyEncryptionAlgorithm() != null) {
            tokenSequence = decryptSignedToken(token, tokenConfiguration);
        }

        JwtContext jwtContext = parseClaims(tokenSequence, tokenConfiguration);
        return new DynamicJsonWebToken(jwtContext.getJwtClaims());
    }

    private static JwtContext parseClaims(String token, TokenConfiguration tokenConfiguration) throws ParseException {
        JwtConsumerBuilder builder = new JwtConsumerBuilder();
        builder.setVerificationKey(tokenConfiguration.getVerificationKey());
        builder.setJwsAlgorithmConstraints(
                new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,
                        tokenConfiguration.getSignatureAlgorithm().getAlgorithm()));

        builder.setRequireExpirationTime();
        builder.setRequireIssuedAt();
        builder.setExpectedIssuer(tokenConfiguration.getIssuer());
        builder.setEvaluationTime(NumericDate.fromSeconds(0));
        List<String> audience = tokenConfiguration.getAudience();
        builder.setExpectedAudience(audience.toArray(new String[audience.size()]));
        JwtConsumer jwtConsumer = builder.build();

        try {
            //  Validate the JWT and process it to the Claims
            JwtContext jwtContext = jwtConsumer.process(token);
            JwtClaims claimsSet = jwtContext.getJwtClaims();
            verifyIatAndExpAndTimeToLive(tokenConfiguration, claimsSet);
            return jwtContext;
        } catch (InvalidJwtException e) {
            throw log.failedToVerifyToken(e);
        }
    }

    private static void verifyIatAndExpAndTimeToLive(TokenConfiguration tokenConfiguration, JwtClaims claimsSet) throws ParseException {
        NumericDate iat;
        NumericDate exp;

        try {
            iat = claimsSet.getIssuedAt();
            exp = claimsSet.getExpirationTime();
        } catch (Exception ex) {
            throw log.invalidIatExp();
        }
        if (iat.getValue() > exp.getValue()) {
            throw log.failedToVerifyIatExp(exp, iat);
        }
        final long maxTimeToLiveSecs = tokenConfiguration.getExpiryTime();

        if (exp.getValue() - iat.getValue() > maxTimeToLiveSecs) {
            throw log.expExceeded(exp, maxTimeToLiveSecs, iat);
        }

    }

    private static String decryptSignedToken(String token, TokenConfiguration tokenConfiguration) throws ParseException {
        try {
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setAlgorithmConstraints(
                    new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,
                            tokenConfiguration.getKeyEncryptionAlgorithm().getAlgorithm()));

            jwe.setKey(tokenConfiguration.getDecryptionKey());
            jwe.setCompactSerialization(token);
            return jwe.getPlaintextString();
        } catch (JoseException e) {
            throw log.encryptedTokenSequenceInvalid(e);
        }
    }

}
