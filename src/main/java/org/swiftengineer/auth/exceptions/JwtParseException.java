package org.swiftengineer.auth.exceptions;

/**
 * @author swift
 * @since 1/25/17
 */
public class JwtParseException extends Exception {

    public JwtParseException(String s) {
        super(s);
    }

    public JwtParseException(Throwable throwable) {
        super(throwable);
    }

}