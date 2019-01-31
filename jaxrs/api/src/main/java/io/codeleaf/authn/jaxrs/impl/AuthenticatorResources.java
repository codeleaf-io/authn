package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.impl.AuthenticatorRegistry;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

public final class AuthenticatorResources {

    private final Map<String, Object> resources;

    public AuthenticatorResources(Map<String, Object> resources) {
        this.resources = resources;
    }

    public Collection<Object> getAllResources() {
        return resources.values();
    }

    public static AuthenticatorResources create() {
        Map<String, Object> resources = new LinkedHashMap<>();
        for (String name : AuthenticatorRegistry.getNames(JaxrsRequestAuthenticator.class)) {
            JaxrsRequestAuthenticator authenticator = AuthenticatorRegistry.lookup(name, JaxrsRequestAuthenticator.class);
            Object resource = authenticator.getResource();
            if (resource != null) {
                resources.put(name, resource);
            }
        }
        return new AuthenticatorResources(resources);
    }
}
