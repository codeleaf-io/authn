package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.impl.DefaultAuthenticationContext;
import io.codeleaf.common.utils.StringEncoder;

import java.net.URI;
import java.util.*;

public final class HandshakeState {

    private final URI uri;
    private final List<String> authenticatorNames = new LinkedList<>();
    private AuthenticationContext authenticationContext;

    public HandshakeState(URI uri) {
        this.uri = uri;
    }

    public static HandshakeState decode(String encodedHandshakeState) {
        Objects.requireNonNull(encodedHandshakeState);
        Map<String, String> fields = StringEncoder.decodeMap(encodedHandshakeState);
        URI uri = URI.create(fields.get("u"));
        List<String> authenticatorNames = StringEncoder.decodeList(fields.get("a"));
        HandshakeState handshakeState = new HandshakeState(uri);
        handshakeState.getAuthenticatorNames().addAll(authenticatorNames);
        String identity = fields.get("i");
        if (identity != null) {
            handshakeState.setAuthenticationContext(DefaultAuthenticationContext.create(identity));
        }
        return handshakeState;
    }

    public URI getUri() {
        return uri;
    }

    public List<String> getAuthenticatorNames() {
        return authenticatorNames;
    }

    public AuthenticationContext getAuthenticationContext() {
        return authenticationContext;
    }

    public void setAuthenticationContext(AuthenticationContext authenticationContext) {
        this.authenticationContext = authenticationContext;
    }

    public String encode() {
        Map<String, String> fields = new HashMap<>();
        fields.put("u", uri.toString());
        fields.put("a", StringEncoder.encodeList(authenticatorNames));
        if (authenticationContext != null) {
            fields.put("i", authenticationContext.getIdentity());
        }
        return StringEncoder.encodeMap(fields);
    }
}
