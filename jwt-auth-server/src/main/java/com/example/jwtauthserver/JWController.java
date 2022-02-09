package com.example.jwtauthserver;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

@RestController
public class JWController {
    @GetMapping("/jwt")
    public ResponseEntity<String> getJwt(@RequestParam String memId, @RequestParam Long expiration) {
        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "HS256");
        headers.put("typ", "JWT");

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", memId);
        claims.put("scope", List.of("jw.home"));
        String jwt = Jwts.builder().setHeader(headers)
                .setClaims(claims)
                .setId(UUID.randomUUID().toString())
                .setExpiration(new Date(System.currentTimeMillis() + (expiration * 1000)))
                .signWith(SignatureAlgorithm.HS256, "jwt_test_sign_key".getBytes())
                .compact();
        return new ResponseEntity<>(jwt, HttpStatus.CREATED);
    }
}
