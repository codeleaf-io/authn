package io.codeleaf.authn;

public class NotAuthenticatedException extends AuthenticationException {

    public NotAuthenticatedException(String message) {
        super(message);
    }

    public NotAuthenticatedException(String message, Throwable throwable) {
        super(message, throwable);
    }

    public NotAuthenticatedException() {
    }
}
