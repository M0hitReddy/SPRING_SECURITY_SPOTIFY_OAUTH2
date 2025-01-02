package com.muzer.App.Config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


public class CustomOAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final OAuth2AuthorizedClientService authorizedClientService;

    public CustomOAuth2SuccessHandler(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                        Authentication authentication) throws IOException, ServletException {
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient("spotify", authentication.getName());
        System.out.println(client);
        if (client != null && client.getAccessToken() != null) {
            OAuth2AccessToken accessToken = client.getAccessToken();

            // Prepare token data
            Map<String, String> tokenData = new HashMap<>();
            tokenData.put("accessToken", accessToken.getTokenValue());
            tokenData.put("expiresAt", accessToken.getExpiresAt().toString());
            Cookie cookie = new Cookie("token", accessToken.getTokenValue());
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            cookie.setPath("/");
            cookie.setMaxAge(accessToken.getExpiresAt().getNano());
            cookie.setValue(accessToken.getTokenValue());
            response.addCookie(cookie);
            System.out.println(cookie.getValue());


            // Send token data as JSON response
            response.setContentType("application/json");
            response.getWriter().write(new ObjectMapper().writeValueAsString(tokenData));
            response.getWriter().flush();
        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient("spotify", authentication.getName());
        System.out.println(client);
        if (client != null && client.getAccessToken() != null) {
            OAuth2AccessToken accessToken = client.getAccessToken();

            // Prepare token data
            Map<String, String> tokenData = new HashMap<>();
            tokenData.put("accessToken", accessToken.getTokenValue());
            tokenData.put("expiresAt", accessToken.getExpiresAt().toString());
            Cookie cookie = new Cookie("token", accessToken.getTokenValue());
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            cookie.setPath("/");
            cookie.setMaxAge(accessToken.getExpiresAt().getNano());
            cookie.setValue(accessToken.getTokenValue());
            response.addCookie(cookie);
            System.out.println(cookie.getValue());


            // Send token data as JSON response
//            response.setContentType("application/json");
//            response.getWriter().write(new ObjectMapper().writeValueAsString(tokenData));
//            response.getWriter().flush();
        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}
