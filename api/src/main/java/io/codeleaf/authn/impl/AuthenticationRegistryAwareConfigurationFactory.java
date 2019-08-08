package io.codeleaf.authn.impl;

import io.codeleaf.config.Configuration;
import io.codeleaf.config.impl.ContextAwareConfigurationFactory;

import java.util.function.Supplier;

public abstract class AuthenticationRegistryAwareConfigurationFactory<T extends Configuration> extends ContextAwareConfigurationFactory<T, AuthenticatorRegistry> {

    public AuthenticationRegistryAwareConfigurationFactory(Class<T> configurationTypeClass) {
        super(configurationTypeClass, AuthenticatorRegistry.class);
    }

    public AuthenticationRegistryAwareConfigurationFactory(T defaultConfiguration) {
        super(AuthenticatorRegistry.class, defaultConfiguration);
    }

    public AuthenticationRegistryAwareConfigurationFactory(Class<T> configurationTypeClass, Class<AuthenticatorRegistry> contextTypeClass, T defaultConfiguration, Supplier<AuthenticatorRegistry> defaultContextProvider) {
        super(configurationTypeClass, contextTypeClass, defaultConfiguration, defaultContextProvider);
    }
}
