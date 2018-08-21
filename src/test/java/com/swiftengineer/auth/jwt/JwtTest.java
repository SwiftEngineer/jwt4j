package com.swiftengineer.auth.jwt;

import com.swiftengineer.auth.development.ValidTestCredentialGenerator;
import net.minidev.json.JSONObject;
import org.junit.Before;
import org.junit.Test;

import java.sql.Date;

import static org.junit.Assert.assertEquals;

/**
 * @author swift
 * @since 2/8/17
 */
public class JwtTest {

    private ValidTestCredentialGenerator testCredentialGenerator;

    @Before
    public void createCredentials() throws Exception {
        // generate valid test credentials
        this.testCredentialGenerator = new ValidTestCredentialGenerator();
    }

    @Test
    public void testCreation() throws Exception {
        // use a set date
        Date issueDate = new Date(1486594305L);

        // create a valid set of some of the supported JWT claims that expires 30 minutes from now
        JwtClaims claims = JwtClaims.JwtClaimsBuilder.newInstance()
                .addIssuedAt(issueDate)
                .addEmail("taylor.swift@github.com")
                .addSubject("1337")
                .addRoles("SUPER_ADMIN")
                .addFirstName("Taylor")
                .addLastName("Swift")
                .build();

        // create an issuer
        JwtIssuer jwtIssuer = new JwtIssuer(
                testCredentialGenerator.getTestKey(),
                testCredentialGenerator.getTestCertificate()
        );

        // create the serialized jwt
        String serializedJwt = jwtIssuer.issueToken(claims);

        // create an actual jwt from the serialized one.
        Jwt createdJwt = Jwt.newFromString(serializedJwt);

        // assert that the claims, even after being serialized still contain the approximate date we want
        JSONObject jsonClaims = createdJwt.getJwsObject().getPayload().toJSONObject();
        assertEquals(1486594L, jsonClaims.get(JwtClaims.ISSUED_AT));
        assertEquals("taylor.swift@github.com", jsonClaims.get(JwtClaims.EMAIL));
        assertEquals("1337", jsonClaims.get(JwtClaims.SUBJECT));
        assertEquals("SUPER_ADMIN", jsonClaims.get(JwtClaims.ROLES));
        assertEquals("Taylor", jsonClaims.get(JwtClaims.FIRST_NAME));
        assertEquals("Swift", jsonClaims.get(JwtClaims.LAST_NAME));

    }
}
