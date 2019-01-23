package io.codeleaf.authn.password.dummyexample;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.impl.DefaultAuthenticationContext;
import io.codeleaf.authn.password.spi.PasswordRequestAuthenticator;

public final class DummyExamplePasswordRequestAuthenticator implements PasswordRequestAuthenticator {
    private static final String DUMMY_USER = "dummy";
    private static final String DUMMY_PASSWORD = "dummy";

    @Override
    public AuthenticationContext authenticate(String userName, String password) {
        return DUMMY_USER.equals(userName) && DUMMY_PASSWORD.equals(password) ?
                DefaultAuthenticationContext.create(DUMMY_USER) : null;
    }
}