package com.example.spring_security_jwt.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class TestController {
    @GetMapping("/all")
    public String allAccess() {
        return "Public Content.";
    }

    @GetMapping("/client")
    @PreAuthorize("hasRole('CLIENT') or hasRole('DOC') or hasRole('ADMIN')")
    public String userAccess() {
        return "Client Content.";
    }

    @GetMapping("/doc")
    @PreAuthorize("hasRole('DOC')")
    public String moderatorAccess() {
        return "Doc Board.";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {
        return "Admin Board.";
    }
}
