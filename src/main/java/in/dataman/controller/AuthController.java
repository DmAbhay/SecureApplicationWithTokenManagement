package in.dataman.controller;

import in.dataman.dto.AuthRequestDTO;
import in.dataman.entity.UserEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import in.dataman.jwt.JwtTokenUtil;
import in.dataman.service.CustomUserDetailsService;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@RestController
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody AuthRequestDTO authRequest) {
        try {
            // Authenticate the user
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
            );
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        // Fetch user details
        UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.getUsername());

        // Generate JWT token
        String token = jwtTokenUtil.generateToken(userDetails.getUsername());
        
        // Optionally, store the token in a cache (e.g., Redis) with the associated username for further validation

        return ResponseEntity.ok(token);
    }

    @PostMapping("/log")
    public String test(){
        return "jai shree krishna";
    }



    @PostMapping("/register")
    public String registerNewUser(@RequestBody UserEntity user) {

        userDetailsService.registerUser(user);

        return "user registered successfully";

    }

    @GetMapping("/secured")
    public String securedEndpoint( @RequestHeader(value = "Authorization", required = true) String token) {
        return "You have accessed a secured endpoint!";
    }

}


