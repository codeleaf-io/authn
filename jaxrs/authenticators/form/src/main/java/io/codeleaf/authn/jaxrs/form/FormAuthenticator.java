package io.codeleaf.authn.jaxrs.form;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.jaxrs.impl.HandshakeSession;
import io.codeleaf.authn.jaxrs.impl.HtmlUtil;
import io.codeleaf.authn.jaxrs.spi.Authenticate;
import io.codeleaf.authn.jaxrs.spi.HandshakeState;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;
import io.codeleaf.common.utils.Types;

import javax.ws.rs.*;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.util.Map;

public final class FormAuthenticator implements JaxrsRequestAuthenticator, HandshakeSession.SessionAware {

    private final FormConfiguration configuration;
    private HandshakeSession session;

    public FormAuthenticator(FormConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public void init(HandshakeSession session) {
        this.session = session;
    }

    private URI getLoginUri() {
        return URI.create("/" + configuration.getContextField() + session.getExecutor().getAuthenticatorUri().toString() + "/login");
    }

    private URI getFormUri() {
        return configuration.getCustomLoginFormUri() == null ? getLoginUri() : configuration.getCustomLoginFormUri();
    }

    @Override
    public String getAuthenticationScheme() {
        return "FORM";
    }

    @Override
    public Response.ResponseBuilder onNotAuthenticated(ContainerRequestContext requestContext) {
        return Response.seeOther(UriBuilder.fromUri(getFormUri())
                .queryParam("loginUri", getLoginUri().toString())
                .queryParam(configuration.getContextField(), session.getState().encode())
                .build());
    }

    public Object getResource() {
        return this;
    }

    @GET
    @Path("/login")
    @Produces(MediaType.TEXT_HTML)
    public String getForm() {
        HandshakeState state = session.getState();
        return "<html><body><h1>Login</h1>\n"
                + "<form method=\"POST\" action=\"" + HtmlUtil.htmlEncode(getLoginUri().toString()) + "\">\n"
                + "Username <input type=\"text\" name=\"" + HtmlUtil.htmlEncode(configuration.getUsernameField()) + "\"><br/>\n"
                + "Password <input type=\"password\" name=\"" + HtmlUtil.htmlEncode(configuration.getPasswordField()) + "\"><br/>\n"
                + "<input type=\"hidden\" name=\"" + HtmlUtil.htmlEncode(configuration.getContextField()) + "\" value=\"" + HtmlUtil.htmlEncode(state.encode()) + "\">\n"
                + "<input type=\"submit\" value=\"Log In\"><br/>\n"
                + "</form></body></html>\n";
    }

    @Override
    public HandshakeState setHandshakeState(ContainerRequestContext requestContext, ResourceInfo resourceInfo, HandshakeState extractedState) throws IOException {
        HandshakeState state = null;
        if (extractedState != null) {
            System.out.println("Leveraging existing handshake!");
            state = extractedState;
        }
        //TODO: Check content-type
        if ("POST".equals(requestContext.getMethod())) {
            System.out.println("Parsing form...");
            Map<String, String> parsedFields = HtmlUtil.decodeForm(requestContext.getEntityStream());
            session.getAttributes().put("parsedFields", parsedFields);
            if (state == null && parsedFields.containsKey(configuration.getContextField())) {
                String encodedState = parsedFields.get(configuration.getContextField());
                state = HandshakeState.decode(encodedState);
            }
        }
        return state;
    }

    @Authenticate
    @POST
    @Path("/login")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public AuthenticationContext extractCredentials() throws AuthenticationException {
        AuthenticationContext authenticationContext;
        System.out.println("Attributes: " + session.getAttributes());
        Map<String, String> parsedFields = Types.cast(session.getAttributes().get("parsedFields"));
        if (parsedFields == null) {
            throw new AuthenticationException();
        }
        if (parsedFields.containsKey(configuration.getUsernameField())
                && parsedFields.containsKey(configuration.getPasswordField())) {
            authenticationContext = configuration.getAuthenticator().authenticate(
                    parsedFields.get(configuration.getUsernameField()),
                    parsedFields.get(configuration.getPasswordField()));
        } else {
            authenticationContext = null;
        }
        return authenticationContext;
    }
}