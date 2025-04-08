package com.muzer.App.Controller;

import com.muzer.App.Service.AccessTokenService;
import com.muzer.App.Service.CustomOAuth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/test")
@ConditionalOnProperty(name = "test.controller.enabled", havingValue = "true", matchIfMissing = false)

public class TestController {

    private final OAuth2AuthorizedClientService authorizedClientService;



    @Autowired
    public CustomOAuth2UserService customOAuth2UserService;

    @Autowired
    public ClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    public AccessTokenService accessTokenService;

    public TestController(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    @RequestMapping("/load")
        public String hello() {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) auth;
            OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                    token.getAuthorizedClientRegistrationId(),
                    token.getName());
            var req = new OAuth2UserRequest(clientRegistrationRepository.findByRegistrationId("google"), client.getAccessToken());
            return customOAuth2UserService.loadUser(req).getName();
        }
}
