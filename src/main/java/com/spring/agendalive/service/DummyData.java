package com.spring.agendalive.service;

import com.spring.agendalive.document.ERole;
import com.spring.agendalive.document.Role;
import com.spring.agendalive.document.User;
import com.spring.agendalive.auth.request.SignupRequest;
import com.spring.agendalive.repository.RoleRepository;
import com.spring.agendalive.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.HashSet;
import java.util.Set;

@Service
public class DummyData {

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;


    @PostConstruct
    public void registerUser() {
        Set<String> roleSet = new HashSet<>();
        roleSet.add("user");
        roleSet.add("mod");
        roleSet.add("admin");

        SignupRequest signUpRequest = new SignupRequest();
        signUpRequest.setUsername("admin");
        signUpRequest.setEmail("admin@agendalive.com");
        signUpRequest.setPassword("12345678");
        signUpRequest.setRole(roleSet);

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRoles();
        Set<Role> roles = new HashSet<>();

        strRoles.forEach(role -> {
            switch (role) {
                case "admin":
                    Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                    roles.add(adminRole);

                    break;
                case "mod":
                    Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                    roles.add(modRole);

                    break;
                default:
                    Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                    roles.add(userRole);
            }
        });


        user.setRoles(roles);
        userRepository.save(user);
    }
}
