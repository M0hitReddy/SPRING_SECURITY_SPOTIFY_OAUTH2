package com.muzer.App.Service;

import com.muzer.App.Models.User;
import com.muzer.App.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    @Autowired public UserRepository userRepository;

//    public CustomOAuth2UserService(UserRepository userRepository) {
//        this.userRepository = userRepository;
//    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        try {
            // Extract user details
            String googleId = oAuth2User.getAttribute("sub");
            String email = oAuth2User.getAttribute("email");
            String name = oAuth2User.getAttribute("name");
            String profilePicture = oAuth2User.getAttribute("picture");

            // Check if user exists
            User user = userRepository.findByEmail(email);

            if (user == null) {
                // Create new user
                user = new User();
                user.setGoogleId(googleId);
                user.setEmail(email);
                user.setName(name);
                user.setProfilePicture(profilePicture);

                // Save user and ensure the save operation completes
                user = userRepository.save(user);

                // Add logging to verify save operation
//                log.info("New user created: {}", user);
            } else {
                // Update existing user's information
                user.setGoogleId(googleId);
                user.setName(name);
                user.setProfilePicture(profilePicture);
                user = userRepository.save(user);
//                log.info("Existing user updated: {}", user);
            }

            // Return OAuth2User with updated attributes
            Map<String, Object> attributes = new HashMap<>(oAuth2User.getAttributes());
            attributes.put("userId", user.getId());  // Add database ID to attributes

            return new DefaultOAuth2User(
                    oAuth2User.getAuthorities(),
                    attributes,
                    "email"  // Use email as the name attribute key
            );

        } catch (Exception e) {
//            log.error("Error during OAuth2 user processing", e);
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("processing_error", "Failed to process user data", null)
            );
        }
    }
}