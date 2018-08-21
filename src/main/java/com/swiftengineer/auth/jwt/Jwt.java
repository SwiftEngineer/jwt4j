package com.swiftengineer.auth.jwt;

import com.swiftengineer.auth.exceptions.JwtParseException;
import com.nimbusds.jose.JWSObject;

import java.text.ParseException;

/**
 * @author swift
 * @since 1/25/17
 */
public class Jwt {
    private final JWSObject jwsObject;
    private final String jwtString;

    protected Jwt(JWSObject jwsObject, String jwtString) {
        this.jwsObject = jwsObject;
        this.jwtString = jwtString;
    }

    public static Jwt newFromString(String token) throws JwtParseException {
        try {
            return new Jwt(JWSObject.parse(token), token);
        } catch (ParseException e) {
            throw new JwtParseException(e);
        }
    }

    public JWSObject getJwsObject() {
        return jwsObject;
    }

    /**
     * Returns the original string used to construct the JWT.
     *
     * @return the JWT string
     */
    public String getJwtString() {
        return jwtString;
    }
}
