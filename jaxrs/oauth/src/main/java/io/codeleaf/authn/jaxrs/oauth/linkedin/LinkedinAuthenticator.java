package io.codeleaf.authn.jaxrs.oauth.linkedin;

import com.github.scribejava.apis.LinkedInApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.oauth.OAuth20Service;
import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.impl.DefaultAuthenticationContext;
import io.codeleaf.authn.jaxrs.oauth.OAuthAuthenticator;
import io.codeleaf.authn.jaxrs.oauth.OAuthConfiguration;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Cookie;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class LinkedinAuthenticator extends OAuthAuthenticator {

    private static final String HEADER_VALUE_PREFIX = "Bearer ";
    private static final String HEADER_KEY = "Authorization";
    private final OAuth20Service linkedInService;

    public LinkedinAuthenticator(OAuthConfiguration configuration) {
        linkedInService = getLinkedInOAuthService(configuration);
    }

    public static LinkedinAuthenticator create(OAuthConfiguration configuration) {
        Objects.requireNonNull(configuration);
        return new LinkedinAuthenticator(configuration);
    }

    @Override
    public AuthenticationContext authenticate(ContainerRequestContext requestContext) throws AuthenticationException {
        String authorizarionToken = requestContext.getHeaderString(HEADER_KEY);
        AuthenticationContext authenticationContext = null;
        if (authorizarionToken != null && authorizarionToken.startsWith(HEADER_VALUE_PREFIX) && requestContext.getCookies().get(LinkedinCookie.COOKIE_NAME) != null) {
            authenticationContext = getAuthenticationContext(requestContext, authorizarionToken);
        }
        return authenticationContext;
    }

    private AuthenticationContext getAuthenticationContext(ContainerRequestContext requestContext, String authorizarionToken) {
        Cookie cookie = requestContext.getCookies().get(LinkedinCookie.COOKIE_NAME);
        AuthenticationContext authenticationContext = null;
        Map<String, Object> map = new HashMap<>(StringMapUtil.decodeString(cookie.getValue()));
        LinkedinCookie linkedinCookie = new LinkedinCookie(cookie.getValue());
        if (linkedinCookie.getToken().equals(authorizarionToken.substring(HEADER_VALUE_PREFIX.length()))) {
            authenticationContext = new DefaultAuthenticationContext(new Principal() {
                @Override
                public String getName() {
                    return "Linkedin-" + map.get(LinkedinCookie.TOKEN_TYPE);
                }
            }, map, true);

            //Check if the cookie is expiring in next 5 mins refresh token
            /*if(300000 < linkedinCookie.getExpiresIn().longValue() - Instant.now().toEpochMilli()){
                linkedInService.refreshAccessToken(linkedinCookie.getRefreshToken());
            }*/
        }
        return authenticationContext;
    }

    @Override
    public URI getLoginURI() throws URISyntaxException {
        return new URI(linkedInService.getAuthorizationUrl());
    }

    //TODO: Move this to singleton provider
    private OAuth20Service getLinkedInOAuthService(OAuthConfiguration oAuthConfiguration) {
        return new ServiceBuilder(oAuthConfiguration.getClientId())
                .apiSecret(oAuthConfiguration.getClientSecret())
                .scope(oAuthConfiguration.getScope())
                .callback(oAuthConfiguration.getRedirectUri().toString())
                .state(oAuthConfiguration.getState())
                .build(LinkedInApi20.instance());
    }
}
