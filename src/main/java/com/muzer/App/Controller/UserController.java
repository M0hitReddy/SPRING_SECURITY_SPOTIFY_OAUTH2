package com.muzer.App.Controller;

import com.muzer.App.Service.AccessTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    public AccessTokenService accessTokenService;

    @Autowired
    public OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/me")
    public Object me() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String tokenVal = accessTokenService.getAccessToken();
//        System.out.println("Map ::::: " + );
//        OAuth2AccessToken accessToken = (OAuth2AccessToken) auth;


        return "Access Token: " + tokenVal ;
    }
}
