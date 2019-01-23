package io.codeleaf.authn.impl;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.spi.AuthenticationContextProvider;

public class ThreadLocalAuthenticationContextManager implements AuthenticationContextProvider {

    private final ThreadLocal<AuthenticationContext> authenticationContextThreadLocal = new ThreadLocal<>();

    @Override
    public AuthenticationContext getAuthenticationContext() {
        return authenticationContextThreadLocal.get();
    }

    public void setAuthenticationContext(AuthenticationContext authenticationContext) {
        authenticationContextThreadLocal.set(authenticationContext);
    }

    public void clearAuthenticationContext() {
        authenticationContextThreadLocal.remove();
    }
}
