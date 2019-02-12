package io.codeleaf.authn.jaxrs.basic;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;
import io.codeleaf.authn.password.spi.Credentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.*;
import java.nio.charset.Charset;
import java.util.Base64;

public final class BasicAuthenticator implements JaxrsRequestAuthenticator {

    private static final Logger LOGGER = LoggerFactory.getLogger(BasicAuthenticator.class);

    private static final Charset UTF8 = Charset.forName("UTF-8");
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
        Credentials credentials = extractCredentials(requestContext);
        LOGGER.debug("Found credentials: " + (credentials != null));
        return credentials != null ? configuration.getAuthenticator().authenticate(credentials.getUserName(), credentials.getPassword()) : null;
    }

    private Credentials extractCredentials(ContainerRequestContext requestContext) {
        Credentials headerCredentials = extractHeaderCredentials(requestContext);
        return headerCredentials == null ? extractFormCredentials(requestContext) : headerCredentials;
    }

    private Credentials extractHeaderCredentials(ContainerRequestContext requestContext) {
        try {
            Credentials credentials;
            String basicAuthnHeaderValue = requestContext.getHeaderString(HEADER_KEY);
            if (basicAuthnHeaderValue != null && basicAuthnHeaderValue.startsWith(HEADER_VALUE_PREFIX)) {
                byte[] byteSequence = Base64.getDecoder().decode(basicAuthnHeaderValue.substring(HEADER_VALUE_PREFIX.length()));
                String decodedValue = new String(byteSequence, UTF8);
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

    private Credentials extractFormCredentials(ContainerRequestContext requestContext) {
        if (requestContext.hasEntity() && MediaType.APPLICATION_FORM_URLENCODED_TYPE.equals(requestContext.getMediaType())) {
            try {
                String messageBody = getMessageBody(requestContext.getEntityStream());
                return parseMessageBody(messageBody);
            } catch (IOException cause) {
                LOGGER.warn(cause.getMessage());
            }
        }

        return null;
    }

    private Credentials parseMessageBody(String messageBody) {
        System.out.println(messageBody);
        //TODO: get the body and parse credentials from form data
        return null;
    }

    private String getMessageBody(InputStream entityStream) throws IOException {
        StringBuilder messageBodyBuilder = new StringBuilder();
        try (Reader reader = new BufferedReader(new InputStreamReader(entityStream))) {
            int ch = 0;
            while ((ch = reader.read()) != -1) {
                messageBodyBuilder.append((char) ch);
            }
        }
        return messageBodyBuilder.toString();
    }

    @Override
    public Response.ResponseBuilder onNotAuthenticated(ContainerRequestContext requestContext) {
        return configuration.isForm()
                ? Response.temporaryRedirect(configuration.getFormUri())
                : Response.status(Response.Status.UNAUTHORIZED).header("WWW-Authenticate", "Basic realm=\"" + configuration.getRealm() + "\"");
    }

    @Override
    public Object getResource() {
        return new BasicResource();
    }
}