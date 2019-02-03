package io.codeleaf.authn.jaxrs.oauth.linkedin;

import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;
import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.NotAuthenticatedException;
import io.codeleaf.authn.jaxrs.Authentication;
import io.codeleaf.authn.jaxrs.AuthenticationPolicy;
import io.codeleaf.common.utils.Strings;


import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import javax.ws.rs.core.MediaType;

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
    @Produces(MediaType.TEXT_HTML)
    @Authentication(value = AuthenticationPolicy.OPTIONAL, authenticator = "linkedin")
    public Response parseAccessTokenResponse(@QueryParam("code") String code,
                                             @QueryParam("error") String error,
                                             @QueryParam("error_description") String errorDescription,
                                             @QueryParam("state") String state) throws InterruptedException, ExecutionException, IOException, URISyntaxException {
        if (code != null && !code.isEmpty() && linkedInService.getState().equals(state)) {
            OAuth2AccessToken accessToken = linkedInService.getAccessToken(code);
            Map<String, Object> map = LinkedInDataProvider.getProfileDetails(accessToken, linkedInService);
            return Response.status(Response.Status.OK).entity(getEntityString(accessToken)).cookie(getLinkedInCookie(accessToken, map)).build();
        }
        return Response.status(Response.Status.BAD_REQUEST).entity("Error :" + error + " Description:" + errorDescription).build();
    }

    @GET
    @Path("/linkedin/url")
    @Authentication(value = AuthenticationPolicy.OPTIONAL, authenticator = "linkedin")
    public String getAuthenticationUrl() {
        return linkedInService.getAuthorizationUrl();
    }

    @GET
    @Path("/linkedin/profile")
    @Produces(MediaType.TEXT_HTML)
    @Authentication(value = AuthenticationPolicy.REQUIRED, authenticator = "linkedin")
    public Response getLinkedInProfile() throws NotAuthenticatedException, InterruptedException, ExecutionException, IOException {
        String token = AuthenticationContext.get().getIdentity();
        Map<String, Object> map = LinkedInDataProvider.getProfileDetails(new OAuth2AccessToken(token), linkedInService);
        return Response.status(Response.Status.OK).entity(map).build();
    }

    private LinkedInCookie getLinkedInCookie(OAuth2AccessToken accessToken, Map<String, Object> map) throws UnsupportedEncodingException, URISyntaxException {
        return LinkedInCookie.Factory.create(accessToken, (String) map.get("firstName"), (String) map.get("lastName"), (String) map.get("headline"), Strings.extractHostName(linkedInService.getCallback()));
    }

    private String getEntityString(OAuth2AccessToken accessToken) {
       // AuthenticationContext.get().getAttributes().get(LANDING)
        return "<script type=\"text/javascript\">window.location.href ='http://cybecore.com:3000/sign-in?token="+accessToken.getAccessToken()+"';</script>";
    }
}