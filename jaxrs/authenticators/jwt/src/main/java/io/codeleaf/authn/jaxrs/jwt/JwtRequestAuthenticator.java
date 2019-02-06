package io.codeleaf.authn.jaxrs.jwt;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;
import io.codeleaf.authn.jaxrs.spi.JaxrsSessionIdProtocol;
import io.codeleaf.authn.spi.SessionDataStore;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Response;

public final class JwtRequestAuthenticator implements JaxrsRequestAuthenticator {

    private final JaxrsSessionIdProtocol protocol;
    private final SessionDataStore store;
    private final JwtAuthenticationContextSerializer serializer;

    public JwtRequestAuthenticator(JaxrsSessionIdProtocol protocol, SessionDataStore store, JwtAuthenticationContextSerializer serializer) {
        this.protocol = protocol;
        this.store = store;
        this.serializer = serializer;
    }

    @Override
    public String getAuthenticationScheme() {
        return "JWT";
    }

    @Override
    public AuthenticationContext authenticate(ContainerRequestContext requestContext) throws AuthenticationException {
        AuthenticationContext authenticationContext;
        String sessionId = protocol.getSessionId(requestContext);
        if (sessionId != null) {
            String jwt = store.retrieveSessionData(sessionId);
            authenticationContext = jwt != null ? serializer.deserialize(jwt) : null;
        } else {
            authenticationContext = null;
        }
        return authenticationContext;
    }

    @Override
    public Response.ResponseBuilder onFailureCompleted(ContainerRequestContext requestContext, AuthenticationContext authenticationContext) {
        if (requestContext == null) {
            return null;
        }
        String jwt = serializer.serialize(authenticationContext);
        String sessionId = store.storeSessionData(jwt);
        Response.ResponseBuilder responseBuilder = Response.temporaryRedirect(null); // we need to determine correct URI...
        protocol.setSessionId(responseBuilder, sessionId);
        return responseBuilder;
    }
}
