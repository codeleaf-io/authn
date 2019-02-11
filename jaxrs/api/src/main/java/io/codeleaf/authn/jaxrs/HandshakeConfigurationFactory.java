package io.codeleaf.authn.jaxrs;

import io.codeleaf.authn.jaxrs.protocols.query.QuerySessionIdConfiguration;
import io.codeleaf.authn.jaxrs.protocols.query.QuerySessionIdConfigurationFactory;
import io.codeleaf.authn.jaxrs.protocols.query.QuerySessionIdProtocol;
import io.codeleaf.authn.jaxrs.spi.JaxrsSessionIdProtocol;
import io.codeleaf.authn.spi.SessionDataStore;
import io.codeleaf.authn.stores.client.ClientSessionDataConfiguration;
import io.codeleaf.authn.stores.client.ClientSessionDataConfigurationFactory;
import io.codeleaf.authn.stores.client.ClientSessionDataStore;
import io.codeleaf.config.impl.AbstractConfigurationFactory;
import io.codeleaf.config.spec.InvalidSpecificationException;
import io.codeleaf.config.spec.Specification;

public final class HandshakeConfigurationFactory extends AbstractConfigurationFactory<HandshakeConfiguration> {

    private static final String PROTOCOL_VALUE_QUERY = "query";
    private static final String SESSION_DATA_STORE_VALUE_CLIENT = "client";
    private static final HandshakeConfiguration DEFAULT = new HandshakeConfiguration("/auth", null, null);


    public HandshakeConfigurationFactory() {
        super(DEFAULT);
    }

    @Override
    public HandshakeConfiguration parseConfiguration(Specification specification) throws InvalidSpecificationException {
        if (specification == null) return null;
        try {
            String path = (String) specification.getSetting("handshake", "path").getValue();
            String protocol = (String) specification.getSetting("handshake", "protocol").getValue();
            String store = (String) specification.getValue("handshake","store");
            JaxrsSessionIdProtocol jaxrsSessionIdProtocol = getProtocol(specification, protocol);
            SessionDataStore sessionDataStore = getSessionDataStore(specification, store);
            return new HandshakeConfiguration(path, jaxrsSessionIdProtocol, sessionDataStore);
        } catch (IllegalArgumentException cause) {
            throw new InvalidSpecificationException(specification, "Can't parse specification: " + cause.getMessage(), cause);
        }
    }

    private SessionDataStore getSessionDataStore(Specification specification, String store) throws InvalidSpecificationException {
        SessionDataStore sessionDataStore = null;
        if (store.equals(SESSION_DATA_STORE_VALUE_CLIENT)) {
            ClientSessionDataConfiguration clientSessionDataConfiguration = new ClientSessionDataConfigurationFactory().parseConfiguration(specification);
            sessionDataStore = ClientSessionDataStore.create(clientSessionDataConfiguration);
        }
        return sessionDataStore;
    }

    private JaxrsSessionIdProtocol getProtocol(Specification specification, String protocol) throws InvalidSpecificationException {
        JaxrsSessionIdProtocol jaxrsSessionIdProtocol = null;
        if (protocol.equals(PROTOCOL_VALUE_QUERY)) {
            QuerySessionIdConfiguration querySessionIdConfiguration = new QuerySessionIdConfigurationFactory().parseConfiguration(specification);
            jaxrsSessionIdProtocol = new QuerySessionIdProtocol(querySessionIdConfiguration);
        }
        return jaxrsSessionIdProtocol;
    }
}
