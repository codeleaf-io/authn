package io.codeleaf.authn.impl;

import io.codeleaf.authn.AuthenticationContext;

import java.security.Principal;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

public class DefaultAuthenticationContext implements AuthenticationContext {

    public static DefaultAuthenticationContext create(String identity) {
        Objects.requireNonNull(identity);
        return new DefaultAuthenticationContext(() -> identity, Collections.emptyMap(), false);
    }

    private final Principal principal;
    private final Map<String, Object> attributes;
    private final boolean isSecure;

    public DefaultAuthenticationContext(Principal principal, Map<String, Object> attributes, boolean isSecure) {
        this.principal = principal;
        this.attributes = attributes;
        this.isSecure = isSecure;
    }

    @Override
    public Principal getPrincipal() {
        return principal;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public boolean isSecure() {
        return isSecure;
    }
}
