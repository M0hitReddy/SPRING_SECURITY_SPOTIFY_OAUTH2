package com.muzer.App.Filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


public class AddAuthHeaderFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Extract token from cookies
//        System.out.println(request.getHeader("Authorization"));
        String token = null;
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
//                System.out.println(cookie.getValue());
                if ("idToken".equals(cookie.getName())) {
                    token = cookie.getValue();
                    break;
                }
            }
        }
//        System.out.println(token);

        // If token is found, add it to the Authorization header
        if (token != null) {
            String finalToken = token;
            HttpServletRequest wrappedRequest = new HttpServletRequestWrapper(request) {
                @Override
                public String getHeader(String name) {
                    if ("Authorization".equalsIgnoreCase(name)) {
                        return "Bearer " + finalToken;
                    }
                    return super.getHeader(name);
                }
            };
//            System.out.println("Wrapped Request: " + wrappedRequest.getHeader("Authorization"));


            // Pass the wrapped
//            System.out.println("Wrapped Request: " + wrappedRequest.getHeader("Authorization"));

            filterChain.doFilter(wrappedRequest, response);
            return;
        }
        filterChain.doFilter(request, response);
    }
}
