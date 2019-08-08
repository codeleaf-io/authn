package io.codeleaf.authn.impl;

import java.util.Set;

public interface AuthenticatorRegistry {

    <T> T lookup(String name, Class<T> authenticatorType);

    Set<String> getNames();

    Set<String> getNames(Class<?> authenticatorType);

    Object lookup(String name);

    <T> boolean contains(String name, Class<T> authenticatorType);

    boolean contains(String name);

    void register(String name, Object authenticator);

}
