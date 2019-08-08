package io.codeleaf.authn.impl;

import java.util.Set;

public final class AuthenticatorRegistries {

    private static final AuthenticatorRegistry EMPTY_REGISTRY = unmodifiableRegistry(new DefaultAuthenticatorRegistry());

    private AuthenticatorRegistries() {
    }

    public static AuthenticatorRegistry emptyRegistry() {
        return EMPTY_REGISTRY;
    }

    public static AuthenticatorRegistry unmodifiableRegistry(AuthenticatorRegistry registry) {
        return new AuthenticatorRegistry() {
            @Override
            public <T> T lookup(String name, Class<T> authenticatorType) {
                return registry.lookup(name, authenticatorType);
            }

            @Override
            public Set<String> getNames() {
                return registry.getNames();
            }

            @Override
            public Set<String> getNames(Class<?> authenticatorType) {
                return registry.getNames(authenticatorType);
            }

            @Override
            public Object lookup(String name) {
                return registry.lookup(name);
            }

            @Override
            public <T> boolean contains(String name, Class<T> authenticatorType) {
                return registry.contains(name, authenticatorType);
            }

            @Override
            public boolean contains(String name) {
                return registry.contains(name);
            }

            @Override
            public void register(String name, Object authenticator) {
                throw new UnsupportedOperationException();
            }
        };
    }
}
