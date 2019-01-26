package io.codeleaf.authn.impl;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public final class AuthenticatorRegistry {

    private AuthenticatorRegistry() {
    }

    private static final Map<String, Object> authenticators = new HashMap<>();

    public static <T> T lookup(String name, Class<T> authenticatorType) {
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

    public static Object lookup(String name) {
        Objects.requireNonNull(name);
        System.out.println("lookup for " + name + " in: " + authenticators);
        return authenticators.get(name);
    }

    public static <T> boolean contains(String name, Class<T> authenticatorType) {
        Objects.requireNonNull(name);
        Objects.requireNonNull(authenticatorType);
        return contains(name) && authenticatorType.isAssignableFrom(lookup(name).getClass());
    }

    public static boolean contains(String name) {
        Objects.requireNonNull(name);
        return authenticators.containsKey(name);
    }

    public static void register(String name, Object authenticator) {
        Objects.requireNonNull(name);
        Objects.requireNonNull(authenticator);
        if (authenticators.containsKey(name)) {
            throw new IllegalStateException("Already an authenticator defined with name: " + name);
        }
        authenticators.put(name, authenticator);
    }
}