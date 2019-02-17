package io.codeleaf.authn.jaxrs.form;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.jaxrs.impl.JaxrsRequestAuthenticatorExecutor;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;
import io.codeleaf.authn.password.spi.Credentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

// TODO: move urlDecode/urlEncode and htmlEncode into different classes
public final class FormAuthenticator implements JaxrsRequestAuthenticator, JaxrsRequestAuthenticatorExecutor.ExecutorAware {

    private static final Logger LOGGER = LoggerFactory.getLogger(FormAuthenticator.class);

    private final FormConfiguration configuration;
    private JaxrsRequestAuthenticatorExecutor executor;

    public FormAuthenticator(FormConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public void init(JaxrsRequestAuthenticatorExecutor executor) {
        this.executor = executor;
    }

    @Override
    public String getAuthenticationScheme() {
        return "FORM";
    }

    @Override
    public AuthenticationContext authenticate(ContainerRequestContext requestContext) throws AuthenticationException {
        Credentials credentials = extractFormCredentials(requestContext);
        LOGGER.debug("Found credentials: " + (credentials != null));
        return credentials != null ? configuration.getAuthenticator().authenticate(credentials.getUserName(), credentials.getPassword()) : null;
    }

    private Credentials extractFormCredentials(ContainerRequestContext requestContext) {
        Credentials credentials;
        if (requestContext.hasEntity() && MediaType.APPLICATION_FORM_URLENCODED_TYPE.equals(requestContext.getMediaType())) {
            try {
                String messageBody = getMessageBody(requestContext.getEntityStream());
                credentials = parseMessageBody(messageBody);
            } catch (IOException cause) {
                LOGGER.warn(cause.getMessage());
                credentials = null;
            }
        } else {
            credentials = null;
        }
        return credentials;
    }

    private Credentials parseMessageBody(String messageBody) {
        Credentials credentials;
        Map<String, String> parsedFields = new HashMap<>();
        for (String field : messageBody.split("&")) {
            String[] parts = field.split("=");
            if (parts.length != 2) {
                LOGGER.warn("Invalid entry in form data: " + field);
            } else {
                parsedFields.put(urlDecode(parts[0]), urlDecode(parts[1]));
            }
        }
        if (parsedFields.containsKey(configuration.getUsernameField())
                && parsedFields.containsKey(configuration.getPasswordField())) {
            credentials = Credentials.create(
                    parsedFields.get(configuration.getUsernameField()),
                    parsedFields.get(configuration.getPasswordField()));
        } else {
            credentials = null;
        }
        return credentials;
    }

    private String urlDecode(String part) {
        try {
            return URLDecoder.decode(part, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException ignored) {
            return "";
        }
    }

    private String urlEncode(String part) {
        try {
            return URLEncoder.encode(part, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException ignored) {
            return "";
        }
    }

    private String htmlEncode(String source) {
        return source
                .replaceAll("&", "&amp;")
                .replaceAll("\"", "&quot;")
                .replaceAll("'", "&#39;")
                .replaceAll("<", "&lt;")
                .replaceAll(">", "&gt;");
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
        return configuration.getCustomLoginFormUri() == null
                ? Response.ok(createHtmlPage(requestContext), MediaType.TEXT_HTML_TYPE)
                : Response.seeOther(configuration.getCustomLoginFormUri());
    }

    private String createHtmlPage(ContainerRequestContext requestContext) {
        return "<html><body><h1>Login</h1>\n"
                + "<form method=\"POST\" action=\"" + htmlEncode(requestContext.getUriInfo().getRequestUri().toString()) + "\">\n"
                + "Username <input type=\"text\" name=\"" + htmlEncode(configuration.getUsernameField()) + "\"><br/>\n"
                + "Password <input type=\"password\" name=\"" + htmlEncode(configuration.getPasswordField()) + "\"><br/>\n"
                + "<input type=\"submit\" value=\"Log In\"><br/>\n"
                + "</form></body></html>";
    }
}