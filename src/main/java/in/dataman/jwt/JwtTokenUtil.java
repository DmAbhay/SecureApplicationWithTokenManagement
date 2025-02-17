//package in.dataman.jwt;
//
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.SignatureAlgorithm;
//import io.jsonwebtoken.security.Keys;
//
//import org.springframework.stereotype.Component;
//
//import java.security.Key;
//import java.util.Date;
//import java.util.function.Function;
//
//@Component
//public class JwtTokenUtil {
//
//	private final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
//
//    public String extractUsername(String token) {
//        return extractClaim(token, Claims::getSubject);
//    }
//
//    public Date extractExpiration(String token) {
//        return extractClaim(token, Claims::getExpiration);
//    }
//
//    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
//        @SuppressWarnings("deprecation")
//		final Claims claims = Jwts.parserBuilder()
//                                  .setSigningKey(key)
//                                  .build()
//                                  .parseClaimsJws(token)
//                                  .getBody();
//        return claimsResolver.apply(claims);
//    }
//
//    @SuppressWarnings("deprecation")
//	public String generateToken(String username) {
//        return Jwts.builder()
//                .setSubject(username)
//                .setIssuedAt(new Date())
//                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 10)) // 1 hour expiration
//                .signWith(SignatureAlgorithm.HS256, key)
//                .compact();
//    }
//
//
//    public boolean validateToken(String token, String username) {
//        return (extractUsername(token).equals(username) && !isTokenExpired(token));
//    }
//
//    private boolean isTokenExpired(String token) {
//        return extractExpiration(token).before(new Date());
//    }
//}




//Using ECDSA Algorithm for Signing the token.

//package in.dataman.jwt;
//
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.SignatureAlgorithm;
//import lombok.Getter;
//import org.springframework.stereotype.Component;
//
//import java.security.*;
//import java.security.spec.ECGenParameterSpec;
//import java.util.Date;
//import java.util.UUID;
//import java.util.function.Function;
//
//@Component
//public class JwtTokenUtil {
//
//    private final PrivateKey privateKey;
//    // Get public key for token verification
//    @Getter
//    private final PublicKey publicKey;
//
//    // Constructor to initialize ECDSA keys
//    public JwtTokenUtil() {
//        try {
//            // Generate EC key pair using secp521r1 curve
//            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
//            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp521r1");
//            keyPairGenerator.initialize(ecSpec);
//            KeyPair keyPair = keyPairGenerator.generateKeyPair();
//            this.privateKey = keyPair.getPrivate();
//            this.publicKey = keyPair.getPublic();
//        } catch (Exception e) {
//            throw new RuntimeException("Error initializing ECDSA key pair", e);
//        }
//    }
//
//    // Method to generate a JWT token
//    public String generateToken(String username) {
//        String sessionId = UUID.randomUUID().toString(); // Generate unique session ID
//
//        return Jwts.builder()
//                .setSubject(username)
//                .setIssuedAt(new Date())
//                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour expiration
//                .claim("sessionId", sessionId)
//                .signWith(privateKey, SignatureAlgorithm.ES512) // Sign with private key using ECDSA (secp521r1 curve)
//                .compact();
//    }
//
//    // Validate if the token is expired
//    public boolean isTokenExpired(String token) {
//        final Date expiration = getExpirationDateFromToken(token);
//        return expiration.before(new Date());
//    }
//
//    // Get expiration date from token
//    public Date getExpirationDateFromToken(String token) {
//        return getClaimFromToken(token, Claims::getExpiration);
//    }
//
//    // Extract username from JWT token
//    public String extractUsername(String token) {
//        return extractClaim(token, Claims::getSubject);
//    }
//
//    // Extract a specific claim from the JWT token
//    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
//        final Claims claims = Jwts.parser()
//                .setSigningKey(publicKey) // Use public key for verification
//                .parseClaimsJws(token)
//                .getBody();
//        return claimsResolver.apply(claims);
//    }
//
//    // Get the claim from the JWT token
//    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
//        return extractClaim(token, claimsResolver);
//    }
//
//    // Validate the token
//    public boolean validateToken(String token, String username) {
//        final String usernameFromToken = extractUsername(token);
//        return (usernameFromToken.equals(username) && !isTokenExpired(token));
//    }
//
//}


package in.dataman.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Getter;
import org.springframework.stereotype.Component;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.UUID;
import java.util.function.Function;

@Component
public class JwtTokenUtil {

    private final PrivateKey privateKey;
    // Get public key for token verification
    @Getter
    private final PublicKey publicKey;

    // Constructor to initialize ECDSA keys
    public JwtTokenUtil() {
        try {
            // Generate EC key pair using secp521r1 curve
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp521r1");
            keyPairGenerator.initialize(ecSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            this.privateKey = keyPair.getPrivate();
            this.publicKey = keyPair.getPublic();
        } catch (Exception e) {
            throw new RuntimeException("Error initializing ECDSA key pair", e);
        }
    }

    // Method to generate a JWT token
    public String generateToken(String username) {
        String sessionId = UUID.randomUUID().toString(); // Generate unique session ID

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour expiration
                .claim("sessionId", sessionId)
                .claim("name", "krishna")
                .signWith(privateKey, SignatureAlgorithm.ES512) // Sign with private key using ECDSA (secp521r1 curve)
                .compact();
    }

    // Validate if the token is expired
    public boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration != null && expiration.before(new Date());
    }


    // Get expiration date from token
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    // Extract username from JWT token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractCustomUsername(String token) {
        return extractClaim(token, claims -> claims.get("name", String.class));
    }

    public String extractClaimsByKey(String token, String key) {
        return extractClaim(token, claims -> claims.get(key, String.class));
    }


    // Extract a specific claim from the JWT token
    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(publicKey) // Use public key for verification
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claimsResolver.apply(claims);
    }


    // Get the claim from the JWT token
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        return extractClaim(token, claimsResolver);
    }

    // Validate the token
    public boolean validateToken(String token, String username) {
        final String usernameFromToken = extractUsername(token);
        return (usernameFromToken.equals(username) && !isTokenExpired(token));
    }

}



