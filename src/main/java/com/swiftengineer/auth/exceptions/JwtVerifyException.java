package com.swiftengineer.auth.exceptions;

/**
 * @author swift
 * @since 1/25/17
 */
public class JwtVerifyException extends Exception {
    public JwtVerifyException(String s, Object... args) {
        super(String.format(s, args));
    }

    public JwtVerifyException(String message, Throwable cause) {
        super(message, cause);
    }

    public JwtVerifyException(Throwable throwable) {
        super(throwable);
    }
}
