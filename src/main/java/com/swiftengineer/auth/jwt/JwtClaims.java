package com.swiftengineer.auth.jwt;

import org.joda.time.DateTimeConstants;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * @author swift
 * @since 1/25/17
 */
public class JwtClaims {
    public static final String JWT_ID = "jti";
    public static final String SUBJECT = "sub";
    public static final String AUDIENCE = "aud";
    public static final String ISSUER = "iss";
    public static final String EXPIRATION_TIME = "exp";
    public static final String NOT_BEFORE = "nbf";
    public static final String ISSUED_AT = "iat";
    public static final String EMAIL = "email";
    public static final String ROLES = "scope";
    public static final String FIRST_NAME = "firstName";
    public static final String LAST_NAME = "lastName";

    private final Map<String, Object> claimsMap;

    private JwtClaims(Map<String, Object> claimsMap) {
        this.claimsMap = claimsMap;
    }

    public static final class JwtClaimsBuilder {

        private Map<String, Object> claimsMap;

        private JwtClaimsBuilder() {
            this.claimsMap = new HashMap<String, Object>();
        }

        private JwtClaimsBuilder(Map<String, Object> claimsMap) {
            this.claimsMap = claimsMap;
        }

        public static JwtClaimsBuilder newInstance() {
            return new JwtClaimsBuilder();
        }

        public static JwtClaimsBuilder newInstanceFromClaimsMap(Map<String, Object> claimsMap) {
            return new JwtClaimsBuilder(claimsMap);
        }

        public JwtClaimsBuilder addJwtId(String jwtId) {
            addClaim(JWT_ID, jwtId);
            return this;
        }

        public JwtClaimsBuilder addSubject(String subject) {
            addClaim(SUBJECT, subject);
            return this;
        }

        public JwtClaimsBuilder addAudience(String audience) {
            addClaim(AUDIENCE, audience);
            return this;
        }

        public JwtClaimsBuilder addIssuer(String issuer) {
            addClaim(ISSUER, issuer);
            return this;
        }

        public JwtClaimsBuilder addEmail(String email) {
            addClaim(EMAIL, email);
            return this;
        }

        public JwtClaimsBuilder addExpirationTime(Date expirationTime) {
            addDateClaim(EXPIRATION_TIME, expirationTime);
            return this;
        }

        public JwtClaimsBuilder addIssuedAt(Date issuedAt) {
            addDateClaim(ISSUED_AT, issuedAt);
            return this;
        }

        public JwtClaimsBuilder addNotBefore(Date notBefore) {
            addDateClaim(NOT_BEFORE, notBefore);
            return this;
        }

        public JwtClaimsBuilder addRoles(String roles) {
            addClaim(ROLES, roles);
            return this;
        }

        public JwtClaimsBuilder addFirstName(String firstName) {
            addClaim(FIRST_NAME, firstName);
            return this;
        }

        public JwtClaimsBuilder addLastName(String lastName) {
            addClaim(LAST_NAME, lastName);
            return this;
        }

        private void addClaim(String claim, Object value) {
            claimsMap.put(claim, value);
        }

        private void addDateClaim(String claim, Date date) {
            claimsMap.put(claim, date.getTime() / DateTimeConstants.MILLIS_PER_SECOND);
        }

        public JwtClaims build() {
            return new JwtClaims(claimsMap);
        }
    }

    public Object getClaim(String key) {
        return claimsMap.get(key);
    }

    public String getJwtId() {
        return getClaimAsString(JWT_ID);
    }

    public String getSubject() {
        return getClaimAsString(SUBJECT);
    }

    public String getAudience() {
        return getClaimAsString(AUDIENCE);
    }

    public String getIssuer() {
        return getClaimAsString(ISSUER);
    }

    public String getEmail() {
        return getClaimAsString(EMAIL);
    }

    public Date getIssuedAt() {
        return getClaimAsDate(ISSUED_AT);
    }

    public Date getExpirationTime() {
        return getClaimAsDate(EXPIRATION_TIME);
    }

    public Date getNotBefore() {
        return getClaimAsDate(NOT_BEFORE);
    }

    public String getFirstName() {
        return getClaimAsString(FIRST_NAME);
    }

    public String getLastName() {
        return getClaimAsString(LAST_NAME);
    }

    private String getClaimAsString(String key) {
        if (getClaim(key) == null) {
            return null;
        }
        return getClaim(key).toString();
    }

    private Date getClaimAsDate(String key) {
        if (getClaim(key) == null) {
            return null;
        }
        return new Date((Long) getClaim(key) * DateTimeConstants.MILLIS_PER_SECOND);
    }

    public String getRoles() { return getClaimAsString(ROLES); }

}
