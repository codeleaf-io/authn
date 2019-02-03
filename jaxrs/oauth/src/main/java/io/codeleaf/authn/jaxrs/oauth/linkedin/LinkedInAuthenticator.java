package io.codeleaf.authn.jaxrs.oauth.linkedin;

import com.github.scribejava.core.oauth.OAuth20Service;
import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.impl.DefaultAuthenticationContext;
import io.codeleaf.authn.jaxrs.oauth.OAuthAuthenticator;
import io.codeleaf.authn.jaxrs.oauth.OAuthConfiguration;
import io.codeleaf.common.utils.Strings;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Cookie;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public final class LinkedInAuthenticator extends OAuthAuthenticator {

    private static final String HEADER_VALUE_PREFIX = "Bearer ";
    private static final String HEADER_KEY = "Authorization";

    private final OAuth20Service linkedInService;
    private final LinkedInResource linkedInResource;

    private LinkedInAuthenticator(OAuth20Service linkedInService, LinkedInResource linkedInResource) {
        this.linkedInService = linkedInService;
        this.linkedInResource = linkedInResource;
    }

    public static LinkedInAuthenticator create(OAuthConfiguration configuration) {
        Objects.requireNonNull(configuration);
        OAuth20Service service = LinkedInServiceFactory.create(configuration);
        LinkedInResource resource = new LinkedInResource(service);
        return new LinkedInAuthenticator(service, resource);
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

    private AuthenticationContext getAuthenticationContext(ContainerRequestContext requestContext, String authorizationToken) throws UnsupportedEncodingException {
        Cookie cookie = requestContext.getCookies().get(LinkedInCookie.COOKIE_NAME);
        AuthenticationContext authenticationContext = null;
        Map<String, Object> map = new HashMap<>(Strings.decodeString(Strings.toDecodeBase64UTF8(cookie.getValue())));
        LinkedInCookie linkedinCookie = LinkedInCookie.Factory.create(cookie.getValue(), cookie.getDomain());
        if (linkedinCookie.getToken().equals(authorizationToken.substring(HEADER_VALUE_PREFIX.length()))) {
            authenticationContext = new DefaultAuthenticationContext(() -> (String) map.get(LinkedInCookie.TOKEN), map, true);
        }
        return authenticationContext;
    }

    @Override
    public boolean handleNotAuthenticated(ContainerRequestContext requestContext) {
        return true;
    }

    @Override
    public URI getLoginURI() {
        return URI.create(linkedInService.getAuthorizationUrl());
    }

    @Override
    public Object getResource() {
        return linkedInResource;
    }
}
