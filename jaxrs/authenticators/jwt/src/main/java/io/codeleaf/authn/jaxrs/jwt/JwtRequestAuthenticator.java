package io.codeleaf.authn.jaxrs.jwt;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;

import javax.ws.rs.container.ContainerRequestContext;
import java.io.UnsupportedEncodingException;

public final class JwtRequestAuthenticator implements JaxrsRequestAuthenticator {

    private static final String HEADER_VALUE_PREFIX = "Bearer ";
    private static final String HEADER_KEY = "Authorization";

    @Override
    public String getAuthenticationScheme() {
        return "JWT";
    }

    @Override
    public AuthenticationContext authenticate(ContainerRequestContext requestContext) throws AuthenticationException {
        try {
            String authorizationToken = requestContext.getHeaderString(HEADER_KEY);
            AuthenticationContext authenticationContext;
            if (authorizationToken != null && authorizationToken.startsWith(HEADER_VALUE_PREFIX) && requestContext.getCookies().get(LinkedInCookie.COOKIE_NAME) != null) {
                authenticationContext = getAuthenticationContext(requestContext, authorizationToken);
            } else {
                authenticationContext = null;
            }
            return authenticationContext;
        } catch (UnsupportedEncodingException cause) {
            throw new AuthenticationException("Error in encoding string for cookie.", cause);
        }
    }
}
