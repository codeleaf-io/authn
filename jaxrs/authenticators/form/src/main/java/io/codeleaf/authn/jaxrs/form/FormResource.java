package io.codeleaf.authn.jaxrs.form;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import java.net.URI;

@Path("")
public final class FormResource {

    @Context
    private HttpHeaders headers;

    @POST
    @Path("/login")
    public Response.ResponseBuilder login() {
        String referer = headers.getRequestHeaders().getFirst("Referer");
        return Response.seeOther(URI.create(referer));
    }
}
