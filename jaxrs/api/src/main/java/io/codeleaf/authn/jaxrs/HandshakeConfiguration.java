package io.codeleaf.authn.jaxrs;

import io.codeleaf.authn.jaxrs.spi.JaxrsSessionIdProtocol;
import io.codeleaf.authn.spi.SessionDataStore;
import io.codeleaf.config.Configuration;

public final class HandshakeConfiguration implements Configuration {

    private final String path;
    private final JaxrsSessionIdProtocol protocol;
    private final SessionDataStore store;

    public HandshakeConfiguration(String path, JaxrsSessionIdProtocol protocol, SessionDataStore store) {
        this.path = path;
        this.protocol = protocol;
        this.store = store;
    }

    public String getPath() {
        return path;
    }

    public JaxrsSessionIdProtocol getProtocol() {
        return protocol;
    }

    public SessionDataStore getStore() {
        return store;
    }
}
