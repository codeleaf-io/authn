package io.codeleaf.authn.jaxrs.jwt;

import io.codeleaf.authn.jaxrs.spi.JaxrsSessionIdProtocol;
import io.codeleaf.authn.spi.SessionDataStore;
import io.codeleaf.config.Configuration;

public final class JwtConfiguration implements Configuration {

    private final JaxrsSessionIdProtocol protocol;
    private final SessionDataStore store;
    private final JwtAuthenticationContextSerializer serializer;

    public JwtConfiguration(JaxrsSessionIdProtocol protocol, SessionDataStore store, JwtAuthenticationContextSerializer serializer) {
        this.protocol = protocol;
        this.store = store;
        this.serializer = serializer;
    }

    public JaxrsSessionIdProtocol getProtocol() {
        return protocol;
    }

    public SessionDataStore getStore() {
        return store;
    }

    public JwtAuthenticationContextSerializer getSerializer() {
        return serializer;
    }
}
