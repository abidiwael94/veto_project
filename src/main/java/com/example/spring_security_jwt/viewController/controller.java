package com.example.spring_security_jwt.viewController;

import java.util.HashSet;
import java.util.Set;

import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import com.example.spring_security_jwt.models.ERole;
import com.example.spring_security_jwt.models.Role;
import com.example.spring_security_jwt.models.User;
import com.example.spring_security_jwt.payload.request.LoginRequest;
import com.example.spring_security_jwt.payload.request.SignupRequest;
import com.example.spring_security_jwt.repository.RoleRepository;
import com.example.spring_security_jwt.repository.UserRepository;



@Controller
public class controller {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    // Show Login Page
    @GetMapping("/login")
    public String showLoginPage(Model model) {
        model.addAttribute("loginRequest", new LoginRequest());
        return "login";
    }

    // Handle Login Submission
    @PostMapping("/login")
    public String handleLogin(
            @Valid @ModelAttribute LoginRequest loginRequest,
            BindingResult bindingResult,
            Model model) {
        if (bindingResult.hasErrors()) {
            model.addAttribute("error", "Informations incorrectes"); // Validation failed
            return "login";
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            return "redirect:/dashboard"; // Success - go to dashboard
        } catch (Exception e) {
            model.addAttribute("error", "Nom d'utilisateur ou mot de passe incorrect"); // Invalid login
            return "login";
        }
    }

    // Show Signup Page
    @GetMapping("/signup")
    public String showSignupPage(Model model) {
        model.addAttribute("signupRequest", new SignupRequest());
        return "signup";
    }

    // Handle Signup Submission
    @PostMapping("/signup")
    public String handleSignup(
            @Valid @ModelAttribute SignupRequest signUpRequest,
            BindingResult bindingResult,
            Model model) {
        if (bindingResult.hasErrors()) {
            model.addAttribute("error", "Informations invalides"); // Validation failed
            return "signup"; // Show signup form with error message
        }

        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            model.addAttribute("error", "Nom d'utilisateur déjà existant !"); // Username exists
            return "signup"; // Show signup form with error message
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            model.addAttribute("error", "L'email est déjà utilisé !"); // Email exists
            return "signup"; // Show signup form with error message
        }

        // Create new user account
        User user = new User(
                signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword())
        );

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_CLIENT)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                        break;
                    case "doc":
                        Role modRole = roleRepository.findByName(ERole.ROLE_DOC)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_CLIENT)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        model.addAttribute("success", "Compte créé avec succès !"); // Account successfully created
        return "login"; // Redirect to login page after successful registration
    }

    // Show Dashboard Page
    @GetMapping("/dashboard")
    public String showDashboard() {
        return "dashboard"; // Thymeleaf template for dashboard
    }
}
