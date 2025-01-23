//package in.dataman.config;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.Lazy;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//
//import in.dataman.jwt.JwtAuthenticationFilter;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//
//    @Autowired
//    @Lazy
//    private JwtAuthenticationFilter jwtAuthenticationFilter;
//   
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        return http
//                .csrf(csrf -> csrf.disable())
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/login", "/register", "/secure/api/add-user-details", "/secure/api/checkToken", "/secure/api/get-data",
//                        		"/secure/api/save-user-detail"
//                        		).permitAll()
//                        .anyRequest().authenticated()
//                )
//                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
//                .build();
//    }
//
//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
//        return authConfig.getAuthenticationManager();
//    }
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();  // Use BCrypt for encoding passwords
//    }
//}








//package in.dataman.config;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.Lazy;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//import org.springframework.http.HttpMethod;
//
//import in.dataman.jwt.JwtAuthenticationFilter;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//
//    @Autowired
//    @Lazy
//    private JwtAuthenticationFilter jwtAuthenticationFilter;
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        return http
//                .csrf(csrf -> csrf.disable())
//                .authorizeHttpRequests(auth -> auth
//                        // ✅ Explicitly allow specific POST APIs
//                        .requestMatchers(HttpMethod.POST, 
//                            "/login", 
//                            "/register", 
//                            "/secure/api/add-user-details", 
//                            "/secure/api/checkToken", 
//                            "/secure/api/save-user-detail"
//                        ).permitAll()
//                        
//                        // ✅ Explicitly allow specific GET APIs
//                        .requestMatchers(HttpMethod.GET, 
//                            "/secure/api/get-data", 
//                            "/secure/api/fetch-user-details", 
//                            "/secure/api/get-all-users"
//                        ).permitAll()
//                        
//                        // 🚫 Require authentication for all other GET APIs
//                        .requestMatchers(HttpMethod.GET).authenticated()
//                        
//                        // ✅ Ensure all other requests (any HTTP method) require authentication
//                        .anyRequest().authenticated()
//                )
//                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
//                .build();
//    }
//
//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
//        return authConfig.getAuthenticationManager();
//    }
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();  // Use BCrypt for encoding passwords
//    }
//}




//package in.dataman.config;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.Lazy;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//import org.springframework.http.HttpMethod;
//
//import in.dataman.jwt.JwtAuthenticationFilter;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//
//    @Autowired
//    @Lazy
//    private JwtAuthenticationFilter jwtAuthenticationFilter;
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        return http
//                .csrf(csrf -> csrf.disable())
//                .authorizeHttpRequests(auth -> auth
//                        // ✅ Allow specific POST APIs
//                        .requestMatchers(HttpMethod.POST, 
//                            "/login", 
//                            "/register", 
//                            "/secure/api/add-user-details", 
//                            "/secure/api/checkToken", 
//                            "/secure/api/save-user-detail",
//                            "/secure/api/check-post-simple"
//                        ).permitAll()
//                        
//                        // ✅ Allow specific GET APIs
//                        .requestMatchers(HttpMethod.GET, 
//                            "/secure/api/get-data", 
//                            "/secure/api/fetch-user-details", 
//                            "/secure/api/get-all-users"
//                        ).permitAll()
//                        
////                        // 🚫 Require authentication for other specific GET endpoints
////                        .requestMatchers(HttpMethod.GET, "/secure/api/**").authenticated()
////                        
////                        // ✅ Explicitly secure all DELETE APIs
////                        .requestMatchers(HttpMethod.DELETE, "/secure/api/**").authenticated()
////                        
////                        // ✅ Explicitly secure all PUT APIs
////                        .requestMatchers(HttpMethod.PUT, "/secure/api/**").authenticated()
////                        
////                        // ✅ Explicitly secure all PATCH APIs
////                        .requestMatchers(HttpMethod.PATCH, "/secure/api/**").authenticated()
//                        
//                        // ✅ Catch-All Rule (Enforces authentication on remaining APIs)
//                        .anyRequest().authenticated()
//                )
//                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
//                .build();
//    }
//
//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
//        return authConfig.getAuthenticationManager();
//    }
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();  // Use BCrypt for encoding passwords
//    }
//}
//






// this config will check for both pattern and authentication.

//package in.dataman.config;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.Lazy;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//import org.springframework.http.HttpMethod;
//
//import in.dataman.jwt.JwtAuthenticationFilter;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//
//    @Autowired
//    @Lazy
//    private JwtAuthenticationFilter jwtAuthenticationFilter;
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        return http
//                .csrf(csrf -> csrf.disable())
//                .authorizeHttpRequests(auth -> auth
//                        // ✅ Explicitly Allowed APIs (Pattern Matching First)
//                        .requestMatchers(HttpMethod.POST,
//                            "/login",
//                            "/register"
//                        ).permitAll()
////
////                        .requestMatchers(HttpMethod.GET,
////                            "/secure/api/get-data",
////                            "/secure/api/fetch-user-details"
////                        ).permitAll()
//
//                        // ✅ Protected APIs (Pattern + Token Required)
//                        .requestMatchers(HttpMethod.POST,
//                        		"/secure/api/add-user-details",
//                        		"/secure/api/checkToken",
//                        		"/secure/api/get-data",
//                        		"/secure/api/save-user-detail",
//                        		"/secure/api/check-post-simple"
//                        		).authenticated()
//
//                        .requestMatchers(HttpMethod.GET,
//                        		"/secure/api/get-data",
//                                "/secure/api/checkToken",
//                                "/secure/api/current-users",
//                                "/secured",
//                                "/secure/api/fetch-user-details",
//                                "/secure/api/get-all-users"
//                                ).authenticated()
//
//                        .requestMatchers(HttpMethod.PUT, "/secure/api/**").authenticated()
//                        .requestMatchers(HttpMethod.DELETE, "/secure/api/**").authenticated()
//                        .requestMatchers(HttpMethod.PATCH, "/secure/api/**").authenticated()
//
//                        // 🚫 Deny Access to All Undefined Patterns
//                        .anyRequest().denyAll()
//                )
//                // ✅ Add JWT Filter Before UsernamePasswordAuthenticationFilter
//                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
//                .build();
//    }
//
//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
//        return authConfig.getAuthenticationManager();
//    }
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//}


// this config will also check for both pattern and authentication but this code follows good practice
package in.dataman.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import in.dataman.jwt.JwtAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    @Lazy
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                // Disable CSRF (JWT is stateless and not vulnerable to CSRF attacks)
                .csrf(csrf -> csrf.disable())

                // Configure Authorization Rules
                .authorizeHttpRequests(auth -> auth
                        // 1. Public Endpoints (No Authentication Required)
                        .requestMatchers(HttpMethod.POST,
                                "/login",
                                "/register"
                        ).permitAll()

                        // 2. Authenticated Endpoints (JWT Token Required)
                        .requestMatchers(HttpMethod.POST,
                                "/secure/api/add-user-details",
                                "/secure/api/checkToken",
                                "/secure/api/get-data",
                                "/secure/api/save-user-detail",
                                "/secure/api/check-post-simple"
                        ).authenticated()

                        .requestMatchers(HttpMethod.GET,
                                "/secure/api/get-data",
                                "/secure/api/checkToken",
                                "/secure/api/current-users",
                                "/secured",
                                "/secure/api/fetch-user-details",
                                "/secure/api/get-all-users"
                        ).authenticated()

                        .requestMatchers(HttpMethod.PUT, "/secure/api/**").authenticated()
                        .requestMatchers(HttpMethod.DELETE, "/secure/api/**").authenticated()
                        .requestMatchers(HttpMethod.PATCH, "/secure/api/**").authenticated()

                        // 3. All Other Requests Must Be Authenticated
                        .anyRequest().authenticated()
                )

                // Add Custom JWT Filter Before UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)

                // Build Security Filter Chain
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // Use BCrypt for Password Hashing (Secure and Standard Practice)
        return new BCryptPasswordEncoder();
    }
}


