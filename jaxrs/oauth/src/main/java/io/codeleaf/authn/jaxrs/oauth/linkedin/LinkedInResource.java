package io.codeleaf.authn.jaxrs.oauth.linkedin;

import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

@Produces({"application/json"})
@Consumes({"application/json"})
@Path("/auth")
public final class LinkedInResource {

    private final OAuth20Service linkedInService;

    public LinkedInResource(OAuth20Service linkedInService) {
        this.linkedInService = linkedInService;
    }

    @GET
    @Path("/linkedin")
    public Response parseAccessTokenResponse(@QueryParam("code") String code,
                                             @QueryParam("error") String error,
                                             @QueryParam("error_description") String errorDescription,
                                             @QueryParam("state") String state) throws InterruptedException, ExecutionException, IOException {
        if (code != null && !code.isEmpty() && linkedInService.getState().equals(state)) {
            OAuth2AccessToken accessToken = linkedInService.getAccessToken(code);
            return Response.status(Response.Status.OK).entity(accessToken).cookie(LinkedInCookie.Factory.create(accessToken)).build();
        }
        return Response.status(Response.Status.BAD_REQUEST).entity("Error :" + error + " Description:" + errorDescription).build();
    }
}
