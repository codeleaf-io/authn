package io.codeleaf.authn.spi;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;

public interface AuthenticationContextProvider {

    default void init(Object context) throws AuthenticationException {
    }

    default boolean isAuthenticated() {
        return getAuthenticationContext() != null;
    }

    AuthenticationContext getAuthenticationContext();
}
