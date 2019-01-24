package io.codeleaf.authn.password.spi;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;

public interface PasswordRequestAuthenticator {

    default AuthenticationContext authenticate(String userName, String password) throws AuthenticationException {
        if (userName == null || password == null || userName.isEmpty()) {
            return null;
        }
        return authenticate(Credentials.create(userName, password));
    }

    AuthenticationContext authenticate(Credentials credentials) throws AuthenticationException;
}
