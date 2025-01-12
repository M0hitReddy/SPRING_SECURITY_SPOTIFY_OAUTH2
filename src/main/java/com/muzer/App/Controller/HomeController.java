package com.muzer.App.Controller;

import com.muzer.App.Service.AccessTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class HomeController {

    private final AccessTokenService accessTokenService;

//    @Autowired
    public HomeController(AccessTokenService accessTokenService) {
        this.accessTokenService = accessTokenService;
    }
//    @Autowired
//    public RedisTemplate<String, Object> template;
    @RequestMapping("/")
    public String home() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//        Object obj = template.opsForValue().get("oauth2:client:spotify:31zhwyrlx7img3z24d3rj3nqdewe");

        return "Access Token: " + accessTokenService.getAccessToken() + "   " +  auth;
    }
}