package com.muzer.App.Service;

import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Service;

@Service
public class AccessTokenService {
//    private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;
//
//
//
//    public AccessTokenService(OAuth2AuthorizedClientService oAuth2AuthorizedClientService) {
//        this.oAuth2AuthorizedClientService = oAuth2AuthorizedClientService;
//    }

    @Autowired
    public OAuth2AuthorizedClientService oAuth2AuthorizedClientService;


    public String getAccessToken() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) auth;
        OAuth2AuthorizedClient client = oAuth2AuthorizedClientService.loadAuthorizedClient(
                token.getAuthorizedClientRegistrationId(),
                token.getName());
        return client.getAccessToken().getTokenValue();

    }

}
