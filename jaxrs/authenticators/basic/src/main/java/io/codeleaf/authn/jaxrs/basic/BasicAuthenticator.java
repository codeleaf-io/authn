package io.codeleaf.authn.jaxrs.basic;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;
import io.codeleaf.authn.password.spi.Credentials;
import io.codeleaf.common.utils.StringEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Response;

public final class BasicAuthenticator implements JaxrsRequestAuthenticator {

    private static final Logger LOGGER = LoggerFactory.getLogger(BasicAuthenticator.class);

    private static final String HEADER_VALUE_PREFIX = "Basic ";
    private static final String HEADER_KEY = "Authorization";
    private static final String SEPARATOR = ":";

    private final BasicConfiguration configuration;

    public BasicAuthenticator(BasicConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public String getAuthenticationScheme() {
        return "BASIC";
    }

    @Override
    public AuthenticationContext authenticate(ContainerRequestContext requestContext, AuthenticatorContext authenticatorContext) throws AuthenticationException {
        Credentials credentials = extractHeaderCredentials(requestContext);
        LOGGER.debug("Found credentials: " + (credentials != null));
        return credentials != null ? configuration.getAuthenticator().authenticate(credentials.getUserName(), credentials.getPassword()) : null;
    }

    private Credentials extractHeaderCredentials(ContainerRequestContext requestContext) {
        try {
            Credentials credentials;
            String basicAuthnHeaderValue = requestContext.getHeaderString(HEADER_KEY);
            if (basicAuthnHeaderValue != null && basicAuthnHeaderValue.startsWith(HEADER_VALUE_PREFIX)) {
                String decodedValue = StringEncoder.toDecodedBase64UTF8(basicAuthnHeaderValue.substring(HEADER_VALUE_PREFIX.length()));
                String[] parts = decodedValue.split(SEPARATOR);
                credentials = parts.length == 2 ? Credentials.createOrNull(parts[0], parts[1]) : null;
            } else {
                credentials = null;
            }
            return credentials;
        } catch (IllegalArgumentException cause) {
            LOGGER.warn(cause.getMessage());
            return null;
        }
    }

    @Override
    public Response.ResponseBuilder onNotAuthenticated(ContainerRequestContext requestContext) {
        return configuration.prompt()
                ? Response.status(Response.Status.UNAUTHORIZED).header("WWW-Authenticate", "Basic realm=\"" + configuration.getRealm() + "\"")
                : null;
    }
}