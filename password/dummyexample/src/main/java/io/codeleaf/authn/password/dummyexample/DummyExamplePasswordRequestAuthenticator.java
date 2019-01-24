package io.codeleaf.authn.password.dummyexample;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.impl.DefaultAuthenticationContext;
import io.codeleaf.authn.password.spi.Credentials;
import io.codeleaf.authn.password.spi.PasswordRequestAuthenticator;

public final class DummyExamplePasswordRequestAuthenticator implements PasswordRequestAuthenticator {

    public static final String DUMMY_USER = "dummy";
    public static final String DUMMY_PASSWORD = "dummy";

    @Override
    public AuthenticationContext authenticate(Credentials credentials) {
        return DUMMY_USER.equals(credentials.getUserName()) && DUMMY_PASSWORD.equals(credentials.getPassword()) ?
                DefaultAuthenticationContext.create(DUMMY_USER) : null;
    }
}