package io.codeleaf.authn.jaxrs.basic;


import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
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
}
