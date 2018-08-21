package org.swiftengineer.auth.exceptions;

/**
 * @author swift
 * @since 1/25/17
 */
public class JwtClaimException extends RuntimeException {
    public JwtClaimException(String s) {
        super(s);
    }
}
