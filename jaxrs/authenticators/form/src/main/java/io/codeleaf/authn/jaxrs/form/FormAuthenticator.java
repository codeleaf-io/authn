package io.codeleaf.authn.jaxrs.form;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.jaxrs.impl.HtmlUtil;
import io.codeleaf.authn.jaxrs.impl.JaxrsRequestAuthenticatorExecutor;
import io.codeleaf.authn.jaxrs.spi.Authenticate;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;

import javax.ws.rs.*;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.Map;

public final class FormAuthenticator implements JaxrsRequestAuthenticator, JaxrsRequestAuthenticatorExecutor.ExecutorAware {

    private final FormConfiguration configuration;
    private URI formUrl;

    public FormAuthenticator(FormConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public void init(JaxrsRequestAuthenticatorExecutor executor) {
        if (configuration.getCustomLoginFormUri() == null) {
            formUrl = URI.create(executor.getAuthenticatorUri().toString() + "/login");
        } else {
            formUrl = configuration.getCustomLoginFormUri();
        }
    }

    @Override
    public String getAuthenticationScheme() {
        return "FORM";
    }

    @Override
    public Response.ResponseBuilder onNotAuthenticated(ContainerRequestContext requestContext) {
        return Response.seeOther(formUrl);
    }

    public Object getResource() {
        return this;
    }

    @GET
    @Path("/login")
    @Produces(MediaType.TEXT_HTML)
    public String getForm() {
        return "<html><body><h1>Login</h1>\n"
                + "<form method=\"POST\" action=\"" + HtmlUtil.htmlEncode(formUrl.toString()) + "\">\n"
                + "Username <input type=\"text\" name=\"" + HtmlUtil.htmlEncode(configuration.getUsernameField()) + "\"><br/>\n"
                + "Password <input type=\"password\" name=\"" + HtmlUtil.htmlEncode(configuration.getPasswordField()) + "\"><br/>\n"
                + "<input type=\"submit\" value=\"Log In\"><br/>\n"
                + "</form></body></html>";
    }

    @Authenticate
    @POST
    @Path("/login")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public AuthenticationContext extractCredentials(String formBody) throws AuthenticationException {
        AuthenticationContext authenticationContext;
        Map<String, String> parsedFields = HtmlUtil.decodeForm(formBody);
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