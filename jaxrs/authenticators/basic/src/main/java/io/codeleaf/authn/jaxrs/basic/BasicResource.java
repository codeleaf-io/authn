package io.codeleaf.authn.jaxrs.basic;


import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

@Produces({"text/html"})
@Path("/")
public final class BasicResource {

    private static final String HTML_PAGE = "<!DOCTYPE html>\n" +
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

    @GET
    @Path("/login")
    public Response getLoginForm() {
        return Response.ok(HTML_PAGE).build();
    }
}
