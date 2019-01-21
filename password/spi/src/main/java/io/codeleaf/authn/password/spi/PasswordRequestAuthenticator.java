package io.codeleaf.authn.password.spi;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;

public interface PasswordRequestAuthenticator {
    
    AuthenticationContext authenticate(String userName, String password) throws AuthenticationException;
}
