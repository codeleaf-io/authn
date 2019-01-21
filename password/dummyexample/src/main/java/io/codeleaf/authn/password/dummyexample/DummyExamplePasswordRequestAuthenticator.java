package io.codeleaf.authn.password.dummyexample;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.password.spi.PasswordRequestAuthenticator;

import java.security.Principal;
import java.util.Map;

public class DummyExamplePasswordRequestAuthenticator implements PasswordRequestAuthenticator {
    private static final String DUMMY_USER = "dummy";
    private static final String DUMMY_PASSWORD = "dummy";
    @Override
    public AuthenticationContext authenticate(String userName, String password) throws AuthenticationException {
        return (DUMMY_USER.equals(userName) && DUMMY_PASSWORD.equals(password)) ? new AuthenticationContext() {
            @Override
            public Principal getPrincipal() {
                return new Principal() {
                    @Override
                    public String getName() {
                        return "Dummy";
                    }
                };
            }

            @Override
            public Map<String, Object> getAttributes() {
                return null;
            }

            @Override
            public boolean isSecure() {
                return false;
            }
        } : null;
    }
}