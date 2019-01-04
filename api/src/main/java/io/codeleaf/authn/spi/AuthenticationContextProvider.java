package io.codeleaf.authn.spi;

import io.codeleaf.authn.AuthenticationContext;

public interface AuthenticationContextProvider {

    default boolean isAuthenticated() {
        return getAuthenticationContext() != null;
    }

    AuthenticationContext getAuthenticationContext();
}
