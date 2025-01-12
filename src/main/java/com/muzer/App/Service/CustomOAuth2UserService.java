package com.muzer.App.Service;

import com.muzer.App.Models.User;
import com.muzer.App.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import java.util.Collections;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    public CustomOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

//    public CustomOAuth2UserService(UserRepository userRepository) {
//        this.userRepository = userRepository;
//    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        System.out.println("USER REQUEST::: " + userRequest);
        // Load user details from Google
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // Extract user details
        String googleId = oAuth2User.getAttribute("sub");
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");
        String profilePicture = oAuth2User.getAttribute("picture");

        // Check if the user already exists
        User user = userRepository.findByEmail(email);
        if (user == null) {
            // If user is new, save them to the database
            user = new User();
//            user.setGoogleId(googleId);
            user.setEmail(email);
            user.setName(name);
            user.setProfilePicture(profilePicture);
            userRepository.save(user);
        }
        System.out.println("USER::: " + user);

        // Return OAuth2User with user attributes
        return new DefaultOAuth2User(
                oAuth2User.getAuthorities(),
                oAuth2User.getAttributes(),  // Attributes from Google
                // Roles/authorities
                oAuth2User.getAttribute("name")
        );
    }
}
