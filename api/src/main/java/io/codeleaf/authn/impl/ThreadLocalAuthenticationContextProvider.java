package io.codeleaf.authn.impl;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.spi.AuthenticationContextProvider;

public class ThreadLocalAuthenticationContextProvider implements AuthenticationContextProvider {

    private final ThreadLocal<AuthenticationContext> authenticationContextThreadLocal = new ThreadLocal<>();

    @Override
    public AuthenticationContext getAuthenticationContext() {
        return authenticationContextThreadLocal.get();
    }
}
