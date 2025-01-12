package com.muzer.App.Service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

@Service
public class AccessTokenService {

//    @Autowired
private final OAuth2AuthorizedClientService authorizedClientService;

    public AccessTokenService(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    public String getAccessToken() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("AUTH IS INSTANCE OF:::  " + auth.getClass());
        if (auth instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) auth;
            OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                    token.getAuthorizedClientRegistrationId(),
                    token.getName());
            return client.getAccessToken().getTokenValue();
        } else if (auth.getPrincipal() instanceof OidcUser) {
            OidcUser user = (OidcUser) auth.getPrincipal();
            return user.getIdToken().getTokenValue();
        } else if (auth.getPrincipal() instanceof Jwt) {
//            System.out.println("Jwt ::::: " );
            Jwt jwt = (Jwt) auth.getPrincipal();
            return jwt.getTokenValue();
        }
        return null;
    }
}