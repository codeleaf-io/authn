package io.codeleaf.authn.jaxrs.jwt;

import io.codeleaf.authn.impl.AuthenticationRegistryAwareConfigurationFactory;
import io.codeleaf.authn.impl.AuthenticatorRegistry;
import io.codeleaf.authn.jaxrs.protocols.query.QuerySessionIdConfiguration;
import io.codeleaf.authn.jaxrs.protocols.query.QuerySessionIdProtocol;
import io.codeleaf.authn.jaxrs.spi.JaxrsSessionIdProtocol;
import io.codeleaf.authn.spi.SessionDataStore;
import io.codeleaf.authn.stores.client.ClientSessionDataConfiguration;
import io.codeleaf.authn.stores.client.ClientSessionDataStore;
import io.codeleaf.config.ConfigurationException;
import io.codeleaf.config.ConfigurationNotFoundException;
import io.codeleaf.config.ConfigurationProvider;
import io.codeleaf.config.spec.InvalidSpecificationException;
import io.codeleaf.config.spec.Specification;
import io.codeleaf.config.spec.SpecificationFormatException;
import io.codeleaf.config.spec.SpecificationNotFoundException;
import io.codeleaf.config.util.Specifications;

import java.io.IOException;

public final class JwtConfigurationFactory extends AuthenticationRegistryAwareConfigurationFactory<JwtConfiguration> {

    private static final JwtConfiguration DEFAULT;

    static {
        try {
            DEFAULT = new JwtConfiguration(
                    createDefaultProtocol(),
                    createDefaultStore(),
                    new JwtAuthenticationContextSerializer());
        } catch (ConfigurationException | IOException cause) {
            throw new ExceptionInInitializerError(cause);
        }
    }

    public JwtConfigurationFactory() {
        super(DEFAULT);
    }

    @Override
    public JwtConfiguration parseConfiguration(Specification specification, AuthenticatorRegistry registry) throws InvalidSpecificationException {
        return new JwtConfiguration(
                getProtocol(specification, registry),
                getStore(specification, registry),
                DEFAULT.getSerializer());
    }

    private SessionDataStore getStore(Specification specification, AuthenticatorRegistry registry) throws InvalidSpecificationException {
        SessionDataStore sessionDataStore;
        if (specification.hasSetting("store")) {
            String store = Specifications.parseString(specification, "store");
            sessionDataStore = registry.lookup(store, SessionDataStore.class);
        } else {
            sessionDataStore = DEFAULT.getStore();
        }
        return sessionDataStore;
    }

    private static SessionDataStore createDefaultStore() throws InvalidSpecificationException, SpecificationNotFoundException, SpecificationFormatException, ConfigurationNotFoundException, IOException {
        return ClientSessionDataStore.create(ConfigurationProvider.get().getConfiguration(ClientSessionDataConfiguration.class));
    }

    private JaxrsSessionIdProtocol getProtocol(Specification specification, AuthenticatorRegistry registry) throws InvalidSpecificationException {
        JaxrsSessionIdProtocol jaxrsSessionIdProtocol;
        if (specification.hasSetting("protocol")) {
            String protocol = Specifications.parseString(specification, "protocol");
            jaxrsSessionIdProtocol = registry.lookup(protocol, JaxrsSessionIdProtocol.class);
        } else {
            jaxrsSessionIdProtocol = DEFAULT.getProtocol();
        }
        return jaxrsSessionIdProtocol;
    }

    private static JaxrsSessionIdProtocol createDefaultProtocol() {
        return new QuerySessionIdProtocol(new QuerySessionIdConfiguration("_j"));
    }
}
