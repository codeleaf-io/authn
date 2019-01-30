package io.codeleaf.authn.jaxrs.oauth.linkedin;

import com.github.scribejava.core.oauth.OAuth20Service;
import io.codeleaf.common.utils.SingletonServiceLoader;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.ExecutionException;

@Path("/auth/linkedin")
//TODO: How to add this class in SecureApplication ???
public class LinkedinResource {

    private final OAuth20Service linkedInService;

    public LinkedinResource() {
        linkedInService = SingletonServiceLoader.load(OAuth20Service.class);
    }

    public LinkedinResource(OAuth20Service linkedInService) {
        this.linkedInService = linkedInService;
    }

    @GET
    public Response parseAccessTokenResponse(@PathParam("code") String code,
                                             @PathParam("error") String error,
                                             @PathParam("error_description") String errorDescription,
                                             @PathParam("state") String state) throws InterruptedException, ExecutionException, IOException, URISyntaxException {
        if (code != null && !code.isEmpty() && linkedInService.getState().equals(state)) {
            return Response.seeOther(new URI(linkedInService.getCallback())).cookie(new LinkedinCookie(linkedInService.getAccessToken(code))).build();
        }
        return Response.status(Response.Status.OK).entity("Error :" + error + " Description:" + errorDescription).build();
    }

}
