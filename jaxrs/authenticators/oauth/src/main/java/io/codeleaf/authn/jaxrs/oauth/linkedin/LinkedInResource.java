package io.codeleaf.authn.jaxrs.oauth.linkedin;

import com.github.scribejava.core.model.OAuth2AccessToken;
import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.NotAuthenticatedException;
import io.codeleaf.authn.jaxrs.Authentication;
import io.codeleaf.authn.jaxrs.AuthenticationPolicy;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.concurrent.ExecutionException;

@Produces({"application/json"})
@Consumes({"application/json"})
@Path("/")
public final class LinkedInResource {

    private final LinkedInOAuth20Service linkedInService;

    @Context
    private HttpServletRequest httpServletRequest;

    @Context
    private HttpServletResponse httpServletResponse;

    public LinkedInResource(LinkedInOAuth20Service linkedInService) {
        this.linkedInService = linkedInService;
    }

    @GET
    @Produces(MediaType.TEXT_HTML)
    @Authentication(value = AuthenticationPolicy.OPTIONAL, authenticator = "linkedin")
    public Response parseAccessTokenResponse(@QueryParam("code") String code,
                                             @QueryParam("error") String error,
                                             @QueryParam("error_description") String errorDescription,
                                             @QueryParam("state") String state) throws InterruptedException, ExecutionException, IOException, URISyntaxException {
        if (code != null && !code.isEmpty() && linkedInService.getState().equals(state)) {
            OAuth2AccessToken accessToken = linkedInService.getAccessToken(code);
            Map<String, Object> map = LinkedInDataProvider.getProfileDetails(accessToken, linkedInService);
            map.put(LinkedInCookie.LANDING_PAGE_URL, linkedInService.getLandingPageUrl());
            return Response.status(Response.Status.OK).entity(getEntityString(accessToken)).cookie(getLinkedInCookie(accessToken, map)).build();
        }
        return Response.status(Response.Status.BAD_REQUEST).entity("Error :" + error + " Description:" + errorDescription).build();
    }

    @GET
    @Path("/url")
    @Produces(MediaType.TEXT_PLAIN)
    @Authentication(value = AuthenticationPolicy.OPTIONAL, authenticator = "linkedin")
    public String getAuthenticationUrl() {
        return linkedInService.getAuthorizationUrl();
    }

    @GET
    @Path("/logout")
    @Authentication(value = AuthenticationPolicy.REQUIRED, authenticator = "linkedin")
    public Response getLogout() {
        httpServletResponse.addCookie(LinkedInCookie.eraseCookieData(httpServletRequest.getCookies()));
        return Response.seeOther(URI.create(linkedInService.getLandingPageUrl())).build();
    }

    @GET
    @Path("/profile")
    @Authentication(value = AuthenticationPolicy.REQUIRED, authenticator = "linkedin")
    public Response getLinkedInProfile() throws NotAuthenticatedException, InterruptedException, ExecutionException, IOException {
        String token = AuthenticationContext.get().getIdentity();
        Map<String, Object> map = LinkedInDataProvider.getProfileDetails(new OAuth2AccessToken(token), linkedInService);
        return Response.status(Response.Status.OK).entity(map).build();
    }

    private LinkedInCookie getLinkedInCookie(OAuth2AccessToken accessToken, Map<String, Object> map) throws UnsupportedEncodingException, URISyntaxException {
        return LinkedInCookie.Factory.create(accessToken, (String) map.get("firstName"), (String) map.get("lastName"), (String) map.get("headline"), extractHostName(linkedInService.getCallback()), (String) map.get(LinkedInCookie.LANDING_PAGE_URL));
    }

    // TODO: Used as a domain name... review
    private String extractHostName(String callback) throws URISyntaxException {
        URI uri = new URI(callback);
        String hostname = uri.getHost();
        if (hostname != null) {
            return hostname.startsWith("www.") ? hostname.substring(4) : hostname;
        }
        return hostname;
    }

    private String getEntityString(OAuth2AccessToken accessToken) {
        return "<script type=\"text/javascript\">window.location.href ='" + linkedInService.getLandingPageUrl() + "?token=" + accessToken.getAccessToken() + "';</script>";
    }
}