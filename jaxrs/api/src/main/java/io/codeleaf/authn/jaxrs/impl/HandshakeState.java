package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.common.utils.StringEncoder;

import java.net.URI;
import java.util.*;

public final class HandshakeState {

    private final URI uri;
    private final List<String> authenticatorNames = new LinkedList<>();

    public HandshakeState(URI uri) {
        this.uri = uri;
    }

    public static HandshakeState decode(String encodedHandshakeState) {
        Objects.requireNonNull(encodedHandshakeState);
        Map<String, String> fields = StringEncoder.decodeMap(encodedHandshakeState);
        URI uri = URI.create(fields.get("uri"));
        List<String> authenticatorNames = StringEncoder.decodeList(fields.get("authenticatorNames"));
        HandshakeState handshakeState = new HandshakeState(uri);
        handshakeState.getAuthenticatorNames().addAll(authenticatorNames);
        return handshakeState;
    }

    public URI getUri() {
        return uri;
    }

    public List<String> getAuthenticatorNames() {
        return authenticatorNames;
    }

    public String encode() {
        Map<String, String> fields = new HashMap<>();
        fields.put("uri", uri.toString());
        fields.put("authenticatorNames", StringEncoder.encodeList(authenticatorNames));
        return StringEncoder.encodeMap(fields);
    }
}
