package com.example.jwtAuthentication.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


@Service
public class JwtService {

    private final String SECRET_KEY = "587ea2a9db72d3a16f8b011f6eba97743b4d37a1ff262136392455656eb7b034 "; //jwt min requirement is 256-bit key (I have it in hex format)
    private final Long EXPIRATION_TIME = (long) 20;  // time in minutes


    /**
     * Returns username from incoming JWT token
     */
    public String extractUsername(String jwtToken){
        return extractSpecificClaim(jwtToken, Claims::getSubject); //getSubject returns the subject of the claims in JWT payload, extracts subject field in claims which is often the username or email
    }


    /**
     *Generate a Jwt Token with custom claims, subject (username in our case), and signed with signing key cryptographed with HS256 algo
     */
    public String generateJwtToken(Map<String, Object> extraClaims, UserDetails userDetails){
        return Jwts
                .builder() //jwt token builder
                .claims(extraClaims) //override any claim with same name, if claim value is null then its removed from payload
                .subject(userDetails.getUsername())
                .issuedAt(new Date()) //only accepts Date, LocalDate is better but not supported yet // default constructor is current time in millis
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME*1000*60))
//                .signWith(getSigningKey(), Jwts.SIG.HS256) //didnt use the algorithm as Keys.hmacShaKeyFor already decides this algorithm based on encrypted key size
                .signWith(getSigningKey())
                .compact(); //generate and return jwt token as string
    }


    /**
     * Generate a Jwt Token with userDetails object only
     */
    public String generateJwtToken(UserDetails userDetails){
        return generateJwtToken(new HashMap<>(), userDetails);
    }


    /**
     * Verifies incoming Jwt by validating username and expiration claims
     */
    public boolean isJwtTokenValid(String jwtToken, UserDetails userDetails){
        final String username = extractUsername(jwtToken);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(jwtToken));
    }


    /**
     * Helper function to check if Jwt token is expired or not
     */
    private boolean isTokenExpired(String jwtToken) {
        return extractExpiration(jwtToken).before(new Date());
    }


    /**
     * Helper function to extract expiration Claim from Jwt Token
     */
    private Date extractExpiration(String jwtToken) {
        return extractSpecificClaim(jwtToken, Claims::getExpiration);
    }


    /**
     * Helper function to extract all Claims from incoming JWT token
     */
    private Claims extractAllClaims(String jwtToken){
        return Jwts
                .parser() //parser builder
                .verifyWith(getSigningKey()) //verify token with our secret key
                .build()  //builds and return parser
                .parseSignedClaims(jwtToken) //parses the token
                .getPayload(); //return all claims
    }


    /**
     * Helper function to extract any specific claim from JWT token
     * @param claimsResolver  Type of Claim Needed
     */
    public <T> T extractSpecificClaim(String jwtToken, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(jwtToken);
        return claimsResolver.apply(claims);
    }


    /**
     * Get key used to digitally sign the JWT token
     * The JWT libraries and Java's cryptography APIs work with Key interfaces or SecretKey objects, instead of bytes or Strings.
     */
    private SecretKey getSigningKey(){
        byte[] bytes = Decoders.BASE64.decode(SECRET_KEY); //decode the secret key into BASE64 format, and converting it to bytes
        return Keys.hmacShaKeyFor(bytes); //For keys <= 256 bits, it uses HS256 (HMAC with SHA-256) algorithm to convert secret to a strong Key for jwt
    }
}
