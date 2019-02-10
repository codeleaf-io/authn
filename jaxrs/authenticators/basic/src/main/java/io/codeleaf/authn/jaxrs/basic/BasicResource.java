package io.codeleaf.authn.jaxrs.basic;


import io.codeleaf.authn.AuthenticationException;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Produces({"application/json"})
@Consumes({"application/json"})
@Path("/")
public class BasicResource {

    private final BasicAuthenticator basicAuthenticator;

    private final String htmlPage = "<!DOCTYPE html>\n" +
            "<html lang=\"en\">\n" +
            "<head>\n" +
            "    <meta charset=\"UTF-8\">\n" +
            "    <title>Login </title>\n" +
            "</head>\n" +
            "<body>\n" +
            "<div class=\"login\">\n" +
            "    <div class=\"login-triangle\"></div>\n" +
            "\n" +
            "    <h2 class=\"login-header\">Log in</h2>\n" +
            "\n" +
            "    <form class=\"login-container\">\n" +
            "        <p><input type=\"email\" placeholder=\"Email\"></p>\n" +
            "        <p><input type=\"password\" placeholder=\"Password\"></p>\n" +
            "        <p><input type=\"submit\" value=\"Log in\"></p>\n" +
            "    </form>\n" +
            "</div>\n" +
            "</body>\n" +
            "</html>";

    public BasicResource(BasicAuthenticator basicAuthenticator) {
        this.basicAuthenticator = basicAuthenticator;
    }

    @GET
    @Produces(MediaType.TEXT_HTML)
    @Path("/login")
    public Response getLoginForm() {
        return Response.ok(htmlPage).build();
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/authenticate")
    public Response authenticate(@FormParam("email") String email, @FormParam("password") String password) {
        try {
            if (null != basicAuthenticator.authenticate(null, null)) {
                return Response.ok(basicAuthenticator.toSecureTokenJson(email, password)).build();
            }
        } catch (AuthenticationException cause) {
            System.out.println(cause);
        }
        return Response.status(Response.Status.BAD_REQUEST).entity("{\"Error\" : \"Invalid user name or password!\"}").build();
    }
}
