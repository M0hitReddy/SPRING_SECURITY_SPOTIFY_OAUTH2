package com.muzer.App.Controller;

import com.muzer.App.Models.User;
import com.muzer.App.Repository.UserRepository;
import com.muzer.App.Service.AccessTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    public AccessTokenService accessTokenService;

    @Autowired
    public OAuth2AuthorizedClientService authorizedClientService;
    @Autowired
    public UserRepository userRepository;

    @GetMapping("/me")
    public User me(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        System.out.println(auth.isAuthenticated());
        String tokenVal = accessTokenService.getAccessToken();
//        System.out.println("Map ::::: " + );
        JwtAuthenticationToken accessToken = (JwtAuthenticationToken) auth;
        String email = accessToken.getToken().getClaimAsString("email");
        if(email != null) {
            User user = userRepository.findByEmail(email);
            if(user != null) {
                return user;
            }
            else {
                response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            }
        }



//        User me = new User();
//        me.setGoogleId(accessToken.getToken().getSubject());
//        me.setEmail(accessToken.getToken().getClaimAsString("email"));
//        me.setName(accessToken.getToken().getClaimAsString("name"));
//        me.setProfilePicture(accessToken.getToken().getClaimAsString("picture"));

//        me.setGoogleId(accessToken.);


        return null;
    }


}
