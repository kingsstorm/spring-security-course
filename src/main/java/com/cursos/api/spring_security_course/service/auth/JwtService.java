package com.cursos.api.spring_security_course.service.auth;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {

    @Value("${security.jwt.expiration-in-minutes}")
    private Long EXPIRTATION_IN_MINUTES;

    @Value("${security.jwt.secret_key}")
    private String SECRET_KEY;

    public String generateToken(UserDetails user, Map<String, Object> extraClaims) {

        Date issuedAt = new Date(System.currentTimeMillis());
        Date expiration = new Date(issuedAt.getTime() + EXPIRTATION_IN_MINUTES * 60 * 1000);

        String jwt = Jwts.builder()
                .header()
                    .type("JWT")
                    .and()
                .subject(user.getUsername())
                .issuedAt(issuedAt)
                .expiration(expiration)
                .claims(extraClaims)
                .signWith(generateKey(), Jwts.SIG.HS256)
                .compact();

        return jwt;
    }

    private SecretKey generateKey() {

        byte [] passwordDecoded = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(passwordDecoded);
    }

    public String extractUserName(String jwt) {

        return extractAllClaims (jwt).getSubject();
    }

    private Claims extractAllClaims(String jwt) {

        return Jwts.parser().verifyWith( generateKey() ).build()
                .parseSignedClaims(jwt).getPayload();
    }

    public String extractJwtFromRequest(HttpServletRequest request) {

        String authorizationHeader = request.getHeader("Authorization"); // Bearer jwt
        if(!StringUtils.hasText(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")) {
            return null;
        }
        String jwt = authorizationHeader.split(" ")[1];

        return jwt;
    }

    public Date extractExpiration(String jwt) {
        return extractAllClaims(jwt).getExpiration();
    }
}
