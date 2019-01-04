package io.codeleaf.authn;

public class AuthenticationException extends Exception {

    public AuthenticationException(String message) {
        super(message);
    }

    public AuthenticationException(String message, Throwable throwable) {
        super(message, throwable);
    }

    public AuthenticationException() {
    }
}
