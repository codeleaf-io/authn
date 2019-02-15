package io.codeleaf.authn.jaxrs.jwt;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;
import io.codeleaf.authn.jaxrs.spi.JaxrsSessionIdProtocol;
import io.codeleaf.authn.spi.SessionDataStore;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Response;
import java.util.Objects;

public final class JwtAuthenticator implements JaxrsRequestAuthenticator {

    private final JaxrsSessionIdProtocol protocol;
    private final SessionDataStore store;
    private final JwtAuthenticationContextSerializer serializer;

    private JwtAuthenticator(JaxrsSessionIdProtocol protocol, SessionDataStore store, JwtAuthenticationContextSerializer serializer) {
        this.protocol = protocol;
        this.store = store;
        this.serializer = serializer;
    }

    @Override
    public String getAuthenticationScheme() {
        return "JWT";
    }

    @Override
    public AuthenticationContext authenticate(ContainerRequestContext requestContext, AuthenticatorContext authenticatorContext) throws AuthenticationException {
        AuthenticationContext authenticationContext;
        String sessionId = protocol.getSessionId(requestContext);
        if (sessionId != null) {
            System.out.println("Session id found: " + sessionId);
            String jwt = store.retrieveSessionData(sessionId);
            System.out.println("Session data: " + jwt);
            authenticationContext = jwt != null ? serializer.deserialize(jwt) : null;
        } else {
            System.out.println("No session id found!");
            authenticationContext = null;
        }
        return authenticationContext;
    }

    @Override
    public Response.ResponseBuilder onFailureCompleted(ContainerRequestContext requestContext, AuthenticationContext authenticationContext) {
        if (authenticationContext == null) {
            return null;
        }
        String jwt = serializer.serialize(authenticationContext);
        String sessionId = store.storeSessionData(jwt);
        Response.ResponseBuilder responseBuilder = Response.temporaryRedirect(requestContext.getUriInfo().getRequestUri()); // we need to determine correct URI...
        protocol.setSessionId(requestContext, responseBuilder, sessionId);
        return responseBuilder;
    }

    public static JwtAuthenticator create(JwtConfiguration configuration) {
        Objects.requireNonNull(configuration);
        return new JwtAuthenticator(configuration.getProtocol(), configuration.getStore(), configuration.getSerializer());
    }
}