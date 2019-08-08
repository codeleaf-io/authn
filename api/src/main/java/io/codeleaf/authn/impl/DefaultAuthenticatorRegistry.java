package io.codeleaf.authn.impl;

import java.util.*;

public final class DefaultAuthenticatorRegistry implements AuthenticatorRegistry {

    private final Map<String, Object> authenticators = new HashMap<>();

    @Override
    public <T> T lookup(String name, Class<T> authenticatorType) {
        Objects.requireNonNull(name);
        Objects.requireNonNull(authenticatorType);
        Object authenticator = lookup(name);
        if (authenticator == null) {
            return null;
        }
        if (!authenticatorType.isAssignableFrom(authenticator.getClass())) {
            throw new IllegalArgumentException();
        }
        return authenticatorType.cast(authenticator);
    }

    @Override
    public Set<String> getNames() {
        return Collections.unmodifiableSet(authenticators.keySet());
    }

    @Override
    public Set<String> getNames(Class<?> authenticatorType) {
        Set<String> names = new LinkedHashSet<>();
        for (Map.Entry<String, Object> entry : authenticators.entrySet()) {
            if (authenticatorType.isAssignableFrom(entry.getValue().getClass())) {
                names.add(entry.getKey());
            }
        }
        return names;
    }

    @Override
    public Object lookup(String name) {
        Objects.requireNonNull(name);
        return authenticators.get(name);
    }

    @Override
    public <T> boolean contains(String name, Class<T> authenticatorType) {
        Objects.requireNonNull(name);
        Objects.requireNonNull(authenticatorType);
        return contains(name) && authenticatorType.isAssignableFrom(lookup(name).getClass());
    }

    @Override
    public boolean contains(String name) {
        Objects.requireNonNull(name);
        return authenticators.containsKey(name);
    }

    @Override
    public void register(String name, Object authenticator) {
        Objects.requireNonNull(name);
        Objects.requireNonNull(authenticator);
        if (authenticators.containsKey(name)) {
            throw new IllegalStateException("Already an authenticator defined with name: " + name);
        }
        authenticators.put(name, authenticator);
    }
}
