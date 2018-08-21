package com.swiftengineer.auth.exceptions;

/**
 * @author swift
 * @since 1/29/17
 */
public class JwtIssueException extends Exception {

    public JwtIssueException(Throwable throwable) {
        super(throwable);
    }

    public JwtIssueException(String message, Throwable cause) {
        super(message, cause);
    }
}
