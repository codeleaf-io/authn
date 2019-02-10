package io.codeleaf.authn.jaxrs.impl;

import java.net.URI;
import java.util.LinkedList;
import java.util.List;

public final class HandshakeState {

    private final URI uri;
    private final List<String> authenticatorNames = new LinkedList<>();

    public HandshakeState(URI uri) {
        this.uri = uri;
    }

    public static HandshakeState fromString(String sessionData) {
        return new HandshakeState(getUri(sessionData));
    }

    private static URI getUri(String sessionData) {
        //TODO: implement ...
        return null;
    }

    public URI getUri() {
        return uri;
    }

    public List<String> getAuthenticatorNames() {
        return authenticatorNames;
    }

}
