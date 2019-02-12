package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.impl.AuthenticatorRegistry;
import io.codeleaf.authn.jaxrs.HandshakeConfiguration;
import io.codeleaf.authn.jaxrs.protocols.query.QuerySessionIdConfiguration;
import io.codeleaf.authn.jaxrs.protocols.query.QuerySessionIdProtocol;
import io.codeleaf.authn.jaxrs.spi.JaxrsSessionIdProtocol;
import io.codeleaf.authn.spi.SessionDataStore;
import io.codeleaf.authn.stores.client.ClientSessionDataConfiguration;
import io.codeleaf.authn.stores.client.ClientSessionDataStore;
import io.codeleaf.config.ConfigurationException;
import io.codeleaf.config.ConfigurationNotFoundException;
import io.codeleaf.config.ConfigurationProvider;
import io.codeleaf.config.impl.AbstractConfigurationFactory;
import io.codeleaf.config.spec.*;
import io.codeleaf.config.util.Specifications;

import java.io.IOException;

public final class HandshakeConfigurationFactory extends AbstractConfigurationFactory<HandshakeConfiguration> {

    private static final HandshakeConfiguration DEFAULT;

    static {
        try {
            DEFAULT = new HandshakeConfiguration("/authn", createDefaultProtocol(), createDefaultStore());
        } catch (ConfigurationException | IOException cause) {
            throw new ExceptionInInitializerError(cause);
        }
    }

    public HandshakeConfigurationFactory() {
        super(DEFAULT);
    }

    @Override
    public HandshakeConfiguration parseConfiguration(Specification specification) throws InvalidSpecificationException {
        try {
            return new HandshakeConfiguration(
                    getPath(specification),
                    getProtocol(specification),
                    getStore(specification));
        } catch (IllegalArgumentException cause) {
            throw new InvalidSpecificationException(specification, "Can't parse specification: " + cause.getMessage(), cause);
        }
    }

    private String getPath(Specification specification) throws SettingNotFoundException {
        return specification.hasSetting("path")
                ? Specifications.parseString(specification, "path")
                : DEFAULT.getPath();
    }

    private SessionDataStore getStore(Specification specification) throws InvalidSpecificationException {
        SessionDataStore sessionDataStore;
        if (specification.hasSetting("store")) {
            String store = Specifications.parseString(specification, "store");
            sessionDataStore = AuthenticatorRegistry.lookup(store, SessionDataStore.class);
        } else {
            sessionDataStore = DEFAULT.getStore();
        }
        return sessionDataStore;
    }

    private static SessionDataStore createDefaultStore() throws InvalidSpecificationException, SpecificationNotFoundException, SpecificationFormatException, ConfigurationNotFoundException, IOException {
        return ClientSessionDataStore.create(ConfigurationProvider.get().getConfiguration(ClientSessionDataConfiguration.class));
    }

    private JaxrsSessionIdProtocol getProtocol(Specification specification) throws InvalidSpecificationException {
        JaxrsSessionIdProtocol jaxrsSessionIdProtocol;
        if (specification.hasSetting("protocol")) {
            String protocol = Specifications.parseString(specification, "protocol");
            jaxrsSessionIdProtocol = AuthenticatorRegistry.lookup(protocol, JaxrsSessionIdProtocol.class);
        } else {
            jaxrsSessionIdProtocol = DEFAULT.getProtocol();
        }
        return jaxrsSessionIdProtocol;
    }

    private static JaxrsSessionIdProtocol createDefaultProtocol() throws InvalidSpecificationException, SpecificationNotFoundException, SpecificationFormatException, ConfigurationNotFoundException, IOException {
        return new QuerySessionIdProtocol(ConfigurationProvider.get().getConfiguration(QuerySessionIdConfiguration.class));
    }
}
