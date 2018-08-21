package org.swiftengineer.auth.jwt;

import org.swiftengineer.auth.development.ValidTestCredentialGenerator;
import org.swiftengineer.auth.exceptions.JwtVerifyException;
import net.minidev.json.JSONObject;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Method;
import java.sql.Date;
import java.time.Instant;

/**
 * @author swift
 * @since 2/8/17
 */
public class JwtVerifierTest {

    private JwtVerifier jwtVerifier;
    private JwtVerifier badJwtVerifier;
    private ValidTestCredentialGenerator testCredentialGenerator;
    private Method assertTimeValid;

    private Jwt createJwt(JwtClaims claims) throws Exception {
        this.testCredentialGenerator = new ValidTestCredentialGenerator();
        // create an issuer
        JwtIssuer jwtIssuer = new JwtIssuer(
                testCredentialGenerator.getTestKey(),
                testCredentialGenerator.getTestCertificate()
        );

        String serializedJwt = jwtIssuer.issueToken(claims);

        return Jwt.newFromString(serializedJwt);
    }

    @Before
    public void createCredentials() throws Exception {
        // generate valid test credentials
        this.testCredentialGenerator = new ValidTestCredentialGenerator();
    }

    @Before
    public void createJwtVerifier() {
        String allowedSignerDN = "^.*\\bCN=test-cert\\.hgdata\\.info\\b(?:,.*|\\s*)$";
        jwtVerifier = new JwtVerifier(allowedSignerDN, testCredentialGenerator.getTestCertificate().getPublicKey());
    }

    @Before
    public void createBadJwtVerifier() {
        String allowedSignerDN = "thiswontmatchanything";
        badJwtVerifier = new JwtVerifier(allowedSignerDN, testCredentialGenerator.getTestCertificate().getPublicKey());
    }

    @Before
    public void setAssertTimeValidFunction() throws NoSuchMethodException {
        // get private method from JwtVerifier
        Method assertTimeValid = jwtVerifier
                .getClass().getDeclaredMethod("assertTimeValid", JSONObject.class);

        // make the method accessible
        assertTimeValid.setAccessible(true);

        this.assertTimeValid = assertTimeValid;
    }

    @Test
    public void validJwtCanBeVerified() throws Exception {
        // create a set of JWT claims with that cannot be used until a set time has passed via JwtClaims.NOT_BEFORE
        JwtClaims claims = JwtClaims.JwtClaimsBuilder.newInstance()
                .addIssuedAt(Date.from(Instant.now().minusSeconds(3L * 60))) // issued 3 minutes ago
                .addExpirationTime(Date.from(Instant.now().plusSeconds(30L * 60))) // expires 30 minutes from now
                .build();

        // call it
        jwtVerifier.authenticate(this.createJwt(claims));
    }

    @Test(expected = JwtVerifyException.class)
    public void invalidJwtCanBeVerified() throws Exception {
        // create a set of JWT claims with that cannot be used until a set time has passed via JwtClaims.NOT_BEFORE
        JwtClaims claims = JwtClaims.JwtClaimsBuilder.newInstance()
                .addIssuedAt(Date.from(Instant.now().minusSeconds(3L * 60))) // issued 3 minutes ago
                .addExpirationTime(Date.from(Instant.now().plusSeconds(30L * 60))) // expires 30 minutes from now
                .build();

        // call it
        badJwtVerifier.authenticate(this.createJwt(claims));
    }

    @Test(expected = JwtVerifyException.class)
    public void testJwtCannotBeUsedBeforeValid() throws Exception {

        // create a set of JWT claims with that cannot be used until a set time has passed via JwtClaims.NOT_BEFORE
        JwtClaims claims = JwtClaims.JwtClaimsBuilder.newInstance()
                .addIssuedAt(Date.from(Instant.now()))
                .addNotBefore(Date.from(Instant.now().plusSeconds(5L * 60)))
                .build();

        try {
            // call it
            JSONObject jwtClaimsInJson = this.createJwt(claims).getJwsObject().getPayload().toJSONObject();
            assertTimeValid.invoke(jwtVerifier, jwtClaimsInJson);
        } catch (Exception e) {
            if (e.getCause() instanceof JwtVerifyException) {
                // if the exception it throws is a JwtVerifyException, then we are good!
                throw (JwtVerifyException) e.getCause();
            } else {
                e.printStackTrace();
            }
        }
    }

    @Test(expected = JwtVerifyException.class)
    public void testJwtCannotBeUsedAfterExpiration() throws Exception {

        // create a set of JWT claims with that cannot be used until a set time has passed via JwtClaims.NOT_BEFORE
        JwtClaims claims = JwtClaims.JwtClaimsBuilder.newInstance()
                .addIssuedAt(Date.from(Instant.now().minusSeconds(6L * 60))) // six minutes ago
                .addExpirationTime(Date.from(Instant.now().minusSeconds(3L * 60))) // expired three minutes ago
                .build();

        try {
            // call it
            JSONObject jwtClaimsInJson = this.createJwt(claims).getJwsObject().getPayload().toJSONObject();
            assertTimeValid.invoke(jwtVerifier, jwtClaimsInJson);
        } catch (Exception e) {
            if (e.getCause() instanceof JwtVerifyException) {
                // if the exception it throws is a JwtVerifyExeception, then we are good!
                throw (JwtVerifyException) e.getCause();
            } else {
                e.printStackTrace();
            }
        }
    }

    @Test(expected = JwtVerifyException.class)
    public void testJwtIssueTimeMustBeforeCurrentTime() throws Exception {

        // create a set of JWT claims with that cannot be used until a set time has passed via JwtClaims.NOT_BEFORE
        JwtClaims claims = JwtClaims.JwtClaimsBuilder.newInstance()
                .addIssuedAt(Date.from(Instant.now().plusSeconds(3L * 60))) // three minutes from now
                .build();

        try {
            // call it
            JSONObject jwtClaimsInJson = this.createJwt(claims).getJwsObject().getPayload().toJSONObject();
            assertTimeValid.invoke(jwtVerifier, jwtClaimsInJson);
        } catch (Exception e) {
            if (e.getCause() instanceof JwtVerifyException) {
                // if the exception it throws is a JwtVerifyExeception, then we are good!
                throw (JwtVerifyException) e.getCause();
            } else {
                e.printStackTrace();
            }
        }
    }
}
