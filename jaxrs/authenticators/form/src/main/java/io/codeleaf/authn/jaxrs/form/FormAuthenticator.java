package io.codeleaf.authn.jaxrs.form;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.jaxrs.impl.HandshakeSession;
import io.codeleaf.authn.jaxrs.impl.HtmlUtil;
import io.codeleaf.authn.jaxrs.impl.JaxrsRequestAuthenticatorExecutor;
import io.codeleaf.authn.jaxrs.impl.ZoneHandler;
import io.codeleaf.authn.jaxrs.spi.Authenticate;
import io.codeleaf.authn.jaxrs.spi.HandshakeState;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;
import io.codeleaf.common.utils.StringEncoder;
import io.codeleaf.common.utils.Types;

import javax.ws.rs.*;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.util.List;
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

    private URI getFormUri() {
        URI formUrl;
        JaxrsRequestAuthenticatorExecutor executor = session.getExecutor();
        if (configuration.getCustomLoginFormUri() == null) {
            formUrl = URI.create(executor.getAuthenticatorUri().toString() + "/login");
        } else {
            formUrl = configuration.getCustomLoginFormUri();
        }
        return formUrl;
    }

    @Override
    public String getAuthenticationScheme() {
        return "FORM";
    }

    @Override
    public Response.ResponseBuilder onNotAuthenticated(ContainerRequestContext requestContext) {
        HandshakeState state = ZoneHandler.getHandshakeState(requestContext);
        return Response.seeOther(
                UriBuilder.fromUri(getFormUri())
                        .queryParam("landingPage", state.getUri())
                        .queryParam("authenticators", StringEncoder.encodeList(state.getAuthenticatorNames()))
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
        String landingPage = state.getUri().toString();
        String authenticators = StringEncoder.encodeList(state.getAuthenticatorNames());
        return "<html><body><h1>Login</h1>\n"
                + "<form method=\"POST\" action=\"" + HtmlUtil.htmlEncode(getFormUri().toString()) + "\">\n"
                + "Username <input type=\"text\" name=\"" + HtmlUtil.htmlEncode(configuration.getUsernameField()) + "\"><br/>\n"
                + "Password <input type=\"password\" name=\"" + HtmlUtil.htmlEncode(configuration.getPasswordField()) + "\"><br/>\n"
                + "<input type=\"hidden\" name=\"landingPage\" value=\"" + HtmlUtil.htmlEncode(landingPage) + "\">\n"
                + "<input type=\"hidden\" name=\"authenticators\" value=\"" + HtmlUtil.htmlEncode(authenticators) + "\">\n"
                + "<input type=\"submit\" value=\"Log In\"><br/>\n"
                + "</form></body></html>\n";
    }

    // TODO: make clean
    @Override
    public HandshakeState setHandshakeState(ContainerRequestContext requestContext, ResourceInfo resourceInfo, HandshakeState extractedState) throws IOException {
        HandshakeState state;
        Map<String, String> parsedFields = null;
        if ("POST".equals(requestContext.getMethod())) { // TODO: this should be form content, not just post...!
            System.out.println("Parsing form...");
            parsedFields = HtmlUtil.decodeForm(requestContext.getEntityStream());
            session.getAttributes().put("parsedFields", parsedFields);
        }
        if (extractedState != null) {
            System.out.println("Leveraging existing handshake!");
            state = extractedState;
        } else {
            String landingPage = requestContext.getUriInfo().getQueryParameters().getFirst("landingPage");
            System.out.println("landingPage from query parameter: " + landingPage);
            List<String> authenticators = StringEncoder.decodeList(requestContext.getUriInfo().getQueryParameters().getFirst("authenticators"));
            System.out.println("authenticators from query parameter: " + authenticators);
            if ("POST".equals(requestContext.getMethod())) {
                if (parsedFields.containsKey("landingPage")) {
                    landingPage = parsedFields.get("landingPage");
                    System.out.println("landingPage from form: " + landingPage);
                }
                if (parsedFields.containsKey("authenticators")) {
                    authenticators = StringEncoder.decodeList(parsedFields.get("authenticators"));
                    System.out.println("authenticators from form: " + authenticators);
                }
            }
            if (landingPage != null && !authenticators.isEmpty()) {
                state = new HandshakeState(URI.create(landingPage));
                state.getAuthenticatorNames().addAll(authenticators);
            } else {
                System.err.println("No handshake created: incomplete information!");
                state = null;
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