package in.dataman.controller;


import java.security.Principal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;

import in.dataman.entity.Users;
import in.dataman.jwt.JwtTokenUtil;
import in.dataman.service.CustomUserDetailsService;
import in.dataman.service.UsersService;


@RestController
@RequestMapping("/secure/api")
public class UsersController {
	
	@Autowired 
	private UsersService usersService;
	
	
	@PostMapping("/add-user-details")
	public String addUser(@RequestBody Users user) {
		
		Users userDetail  = usersService.addUser(user);
		
		System.out.println(userDetail);
		
		return "user detail saved successfully";
	}
	
	
	@GetMapping("/current-users")
	public String getCurrentUser(Principal principal) {
		return principal.getName();
	}
	
	
	@Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    // GET endpoint to check if the token is valid for the logged-in user
    @GetMapping("/checkToken")
    public String checkTokenValidity(@RequestHeader(value = "Authorization", required = true) String token) {
        // Extract username from the token
        String username = null;
        try {
            username = jwtTokenUtil.extractUsername(token.substring(7));  // Remove "Bearer " from the token
        } catch (Exception e) {
            return "Invalid token: " + e.getMessage();
        }

        // Check if the token is valid for the user
        if (username != null) {
            if (jwtTokenUtil.validateToken(token.substring(7), username)) {
                return "Token is valid for user: " + username;
            } else {
                return "Invalid or expired token for user: " + username;
            }
        } else {
            return "Token extraction failed";
        }
    }
    
    
    @GetMapping("/get-data")
    public String getData(@RequestHeader(value = "Authorization", required = true) String token, @RequestParam String username) {
        // Extract username from the token
        String tokenExtrackedUsername = null;
        try {
        	tokenExtrackedUsername = jwtTokenUtil.extractUsername(token.substring(7));  // Remove "Bearer " from the token
        } catch (Exception e) {
            return "Invalid token: " + e.getMessage();
        }

        // Check if the token is valid for the user
        if (username != null) {
            if (jwtTokenUtil.validateToken(token.substring(7), username)) {
            	
            	if(!tokenExtrackedUsername.equals(username)) {
            		return "this token is not valid for "+username;
            	}
                return "Token is valid for user: " + username;
            } else {
                return "Invalid or expired token for user: " + username;
            }
        } else {
            return "Token extraction failed";
        }
    }
    
    
    @PostMapping("/sampl-post")
    public ResponseEntity<?> samplePostMethod(
            @RequestHeader(value = "Authorization", required = true) String token, 
            @RequestBody JsonNode user, 
            @RequestParam String username) {
        
        String tokenExtractedUsername = null;
        try {
            tokenExtractedUsername = jwtTokenUtil.extractUsername(token.substring(7));  // Remove "Bearer " from the token
        } catch (Exception e) {
            return ResponseEntity.ok("Invalid token: " + e.getMessage());
        }

        // Check if the token is valid for the user
        if (tokenExtractedUsername != null) {
            if (jwtTokenUtil.validateToken(token.substring(7), username)) {
                
                if (!tokenExtractedUsername.equals(username)) {
                    return ResponseEntity.ok("This token is not valid for " + username);
                }

                // ✅ Token is valid and username matches
                try {
                    // 🔽 ACTUAL BUSINESS LOGIC SHOULD GO HERE 🔽
                    // Example: Save user details to the database
                    

                    return ResponseEntity.ok("write your message when exception come");
                } catch (Exception ex) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body("write your message when failed" + ex.getMessage());
                }

            } else {
                return ResponseEntity.ok("Invalid or expired token for user: " + username);
            }
        } else {
            return ResponseEntity.ok("Token extraction failed");
        }
    }
    
    
    @PostMapping("/save-user-detail")
    public ResponseEntity<?> saveUserDetail(
            @RequestHeader(value = "Authorization", required = true) String token, 
            @RequestBody JsonNode user, 
            @RequestParam String username) {
        
        String tokenExtractedUsername = null;
        try {
            tokenExtractedUsername = jwtTokenUtil.extractUsername(token.substring(7));  // Remove "Bearer " from the token
        } catch (Exception e) {
            return ResponseEntity.ok("Invalid token: " + e.getMessage());
        }

        // Check if the token is valid for the user
        if (tokenExtractedUsername != null) {
            if (jwtTokenUtil.validateToken(token.substring(7), username)) {
                
                if (!tokenExtractedUsername.equals(username)) {
                    return ResponseEntity.ok("This token is not valid for " + username);
                }

                try {
                    String userName = user.has("username") ? user.get("username").asText() : null;
                    String password = user.has("password") ? user.get("password").asText() : null;
                    String email = user.has("email") ? user.get("email").asText() : null;
                    Integer age = user.has("age") ? user.get("age").asInt() : null;

                    if (userName == null || password == null || email == null || age == null) {
                        return ResponseEntity.badRequest().body("Missing required fields in the request body");
                    }

                    Users userObj = new Users();
                    userObj.setUsername(userName);
                    userObj.setPassword(password);
                    userObj.setAge(age);
                    userObj.setEmail(email);
                    
                    usersService.addUser(userObj);

                    return ResponseEntity.ok("User details saved successfully for: " + username);
                } catch (Exception ex) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body("Failed to save user details: " + ex.getMessage());
                }

            } else {
                return ResponseEntity.ok("Invalid or expired token for user: " + username);
            }
        } else {
            return ResponseEntity.ok("Token extraction failed");
        }
    }
    
    @GetMapping("/delete-document")
    public ResponseEntity<?> getAllUsersDetail(@RequestHeader(value = "Authorization", required = true) String token, @RequestParam String username){
    	String tokenExtractedUsername = null;
        try {
            tokenExtractedUsername = jwtTokenUtil.extractUsername(token.substring(7));  // Remove "Bearer " from the token
        } catch (Exception e) {
            return ResponseEntity.ok("Invalid token: " + e.getMessage());
        }

        // Check if the token is valid for the user
        if (tokenExtractedUsername != null) {
            if (jwtTokenUtil.validateToken(token.substring(7), username)) {
                
                if (!tokenExtractedUsername.equals(username)) {
                    return ResponseEntity.ok("This token is not valid for " + username);
                }

                // ✅ Token is valid and username matches
                try {
                    // 🔽 ACTUAL BUSINESS LOGIC SHOULD GO HERE 🔽
                    // Example: Save user details to the database
                	
                	String message = "document deleted successfully";
                    

                    return ResponseEntity.ok(message);
                } catch (Exception ex) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body("write your message when failed" + ex.getMessage());
                }
                
                


            } else {
                return ResponseEntity.ok("Invalid or expired token for user: " + username);
            }
        } else {
            return ResponseEntity.ok("Token extraction failed");
        }
    }
    
    @PostMapping("/check-post")
    public ResponseEntity<?> checkPost(@RequestHeader(value = "Authorization", required = true) String token, @RequestParam String username) {
    	
    	String tokenExtractedUsername = null;
        try {
            tokenExtractedUsername = jwtTokenUtil.extractUsername(token.substring(7));  // Remove "Bearer " from the token
        } catch (Exception e) {
            return ResponseEntity.ok("Invalid token: " + e.getMessage());
        }

        // Check if the token is valid for the user
        if (tokenExtractedUsername != null) {
            if (jwtTokenUtil.validateToken(token.substring(7), username)) {
                
                if (!tokenExtractedUsername.equals(username)) {
                    return ResponseEntity.ok("This token is not valid for " + username);
                }

                // ✅ Token is valid and username matches
                try {
                    // 🔽 ACTUAL BUSINESS LOGIC SHOULD GO HERE 🔽
                    // Example: Save user details to the database
                	
                	String message = "document deleted successfully";
                    

                    return ResponseEntity.ok(message);
                } catch (Exception ex) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body("write your message when failed" + ex.getMessage());
                }
                
                


            } else {
                return ResponseEntity.ok("Invalid or expired token for user: " + username);
            }
        } else {
            return ResponseEntity.ok("Token extraction failed");
        }
    }
    
    
    @PostMapping("/check-post-simple")
    public ResponseEntity<?> checkPostSimple(@RequestHeader(value = "Authorization", required = true) String token) {
            return ResponseEntity.ok("checked simple post"); 
            
            
    }
    
    
    @GetMapping("/check-get-simple")
    public ResponseEntity<?> checkGetSimple(@RequestHeader(value = "Authorization", required = true) String token){
    	return ResponseEntity.ok("checked simple get");
    }


}
