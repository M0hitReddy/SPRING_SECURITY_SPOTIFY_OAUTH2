package com.muzer.App.AuthenticationSpotify;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;


//@Component
public class SpotifyAuthProvider implements AuthenticationProvider {


    @Override
    public Authentication authenticate(Authentication authentication) {
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return false;
    }




}
