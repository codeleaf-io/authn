package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.AuthenticationContext;

import java.net.URI;
import java.util.LinkedList;
import java.util.List;

public final class HandshakeState {

    private AuthenticationContext authenticationContext;
    private URI uri;
    private List<String> authenticatorNames = new LinkedList<>();

    public AuthenticationContext getAuthenticationContext() {
        return authenticationContext;
    }

    public void setAuthenticationContext(AuthenticationContext authenticationContext) {
        this.authenticationContext = authenticationContext;
    }

    public URI getUri() {
        return uri;
    }

    public void setUri(URI uri) {
        this.uri = uri;
    }

    public List<String> getAuthenticatorNames() {
        return authenticatorNames;
    }

    public void setAuthenticatorNames(List<String> authenticatorNames) {
        this.authenticatorNames = authenticatorNames;
    }
}
