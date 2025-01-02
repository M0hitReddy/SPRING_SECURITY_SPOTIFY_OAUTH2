package com.muzer.App.Controller;

import com.muzer.App.Repository.RedisSessionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/session")
public class SessionController {
//    @Autowired
//    public RedisSessionRepository sessionRepository;
        @GetMapping("/all")
        public Object getAllSessions() {
            return "sessionRepository.getAllSessions()";
        }

        @RequestMapping("/logout")
        public String logout() {
            return "Logout";
        }
}
