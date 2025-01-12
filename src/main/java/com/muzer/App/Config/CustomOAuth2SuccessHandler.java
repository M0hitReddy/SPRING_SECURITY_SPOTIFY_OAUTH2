package com.muzer.App.Config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.*;


public class CustomOAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final OAuth2AuthorizedClientService authorizedClientService;

    public CustomOAuth2SuccessHandler(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient("google", authentication.getName());
//        System.out.println(client);
        if (client != null && client.getAccessToken() != null) {
            List<Cookie> cookies = getCookies(client);
//            System.out.println(cookies.get(0).getValue() + "::::" + cookies.get(1).getValue());
            response.addCookie(cookies.get(0));
            response.addCookie(cookies.get(1));
//            System.out.println("c1 ::::: " + cookies.get(0).getMaxAge());
//            System.out.println("c2 ::::: " + cookies.get(1).getMaxAge());
            response.sendRedirect("http://localhost:5173/callback?success=true");
//            System.out.println(cookie.getValue());


            // Send token data as JSON response
//            response.setContentType("application/json");
//            response.getWriter().write(new ObjectMapper().writeValueAsString(tokenData));
//            response.getWriter().flush();
        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    private static List<Cookie> getCookies(OAuth2AuthorizedClient client) {
        OAuth2AccessToken accessToken = client.getAccessToken();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        DefaultOidcUser idToken = (DefaultOidcUser) authentication.getPrincipal();
//        System.out.println(idToken.getIdToken().getTokenValue());


        // Prepare token data
        List<Cookie> cookies = new ArrayList<>();
//        Map<String, String> tokenData = new HashMap<>();
//        tokenData.put("accessToken", accessToken.getTokenValue());
//        tokenData.put("expiresAt", accessToken.getExpiresAt().toString());
//        Map<String, String> idTokenData = new HashMap<>();
//        idTokenData.put("idToken", idToken.getIdToken().getTokenValue());
//        idTokenData.put("expiresAt", idToken.getExpiresAt().toString());

        Cookie cookie1 = new Cookie("token", accessToken.getTokenValue());
        cookie1.setHttpOnly(true);
        cookie1.setSecure(true);
        cookie1.setPath("/");
        cookie1.setMaxAge(Objects.requireNonNull(accessToken.getExpiresAt()).getNano());
        cookie1.setValue(accessToken.getTokenValue());

        Cookie cookie2 = new Cookie("idToken", idToken.getIdToken().getTokenValue());
        cookie2.setHttpOnly(true);
        cookie2.setSecure(true);
        cookie2.setPath("/");
        cookie2.setMaxAge((int) (idToken.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond()));        cookie2.setValue(idToken.getIdToken().getTokenValue());
        cookies.add(cookie1);
        cookies.add(cookie2);
        System.out.println("c1 ::::: " + accessToken.getExpiresAt());
        System.out.println("c2 ::::: " + idToken.getExpiresAt());
        return cookies;
    }
}
