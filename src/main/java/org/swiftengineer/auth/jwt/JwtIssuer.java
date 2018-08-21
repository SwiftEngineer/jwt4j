package org.swiftengineer.auth.jwt;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import org.swiftengineer.auth.exceptions.JwtIssueException;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.UUID;

/**
 * @author swift
 * @since 1/29/17
 */
public class JwtIssuer {
    private static final Logger LOGGER = LogManager.getLogger(JwtIssuer.class);

    /**
     * Private portion of the key used for signing the JWT
     */
    private RSAPrivateKey privateKey;

    /**
     * Certificate of the key used to sign the JWT
     */
    private X509Certificate signingCertificate;


    public JwtIssuer(RSAPrivateKey privateKey, X509Certificate signingCertificate) {
        this.privateKey = privateKey;
        this.signingCertificate = signingCertificate;
    }

    /**
     * Used to create a JWT
     * @param claims to create a JWT for
     * @return String that is the signed and serialized JWT
     * @throws JwtIssueException when JWT cannot be issued
     */
    public String issueToken(JwtClaims claims) throws JwtIssueException {
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder();

        // parse or assign JWT id
        if (Strings.isNullOrEmpty(claims.getJwtId())) {
            claimsSetBuilder.jwtID(UUID.randomUUID().toString());
        } else {
            claimsSetBuilder.jwtID(claims.getJwtId());
        }

        // build claims, most of these are standardized by the JOSE JWT spec.
        claimsSetBuilder.subject(claims.getSubject());
        claimsSetBuilder.issueTime(claims.getIssuedAt());
        claimsSetBuilder.notBeforeTime(claims.getNotBefore());
        claimsSetBuilder.expirationTime(claims.getExpirationTime());
        claimsSetBuilder.claim("email", claims.getEmail());
        claimsSetBuilder.claim("scope", claims.getRoles());
        claimsSetBuilder.claim("firstName", claims.getFirstName());
        claimsSetBuilder.claim("lastName", claims.getLastName());

        // build header
        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256);

        // Get issuer through signing certificate or a claim inside the JWT
        // Put the signing certificate in the header if present. This allows verifier to follow the certificate chain
        // back to the root for verification.
        if (signingCertificate != null) {
            if (!Strings.isNullOrEmpty(claims.getIssuer())) {
                LOGGER.warn("Issuer " +
                        claims.getIssuer() +
                        " passed in from claims will be ignored. Issuer is determined from signing certificate: "
                        + signingCertificate.getSubjectDN().getName()
                );
            }
            LOGGER.info("DN: " + signingCertificate.getSubjectDN());
            claimsSetBuilder.issuer(signingCertificate.getSubjectDN().getName());
            try {
                headerBuilder.x509CertChain(ImmutableList.of(Base64.encode(signingCertificate.getEncoded())));
            } catch (CertificateEncodingException e) {
                String message = String.format("Failed to get encoded value for signing certificate. Subject: '%s'",
                        signingCertificate.getSubjectDN());
                throw new JwtIssueException(message, e);
            }
        } else {
            claimsSetBuilder.issuer(claims.getIssuer());
        }

        // sign the jwt
        JWSObject jwsObject = new JWSObject(headerBuilder.build(), new Payload(claimsSetBuilder.build().toJSONObject()));
        RSASSASigner rsaSigner = new RSASSASigner(privateKey);

        try {
            jwsObject.sign(rsaSigner);
        } catch (JOSEException e) {
            throw new JwtIssueException("An error occurred while signing the JWT", e);
        }

        // serialize it
        return jwsObject.serialize();
    }
}
