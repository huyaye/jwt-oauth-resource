package com.example.jwtauthserver;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

@Service
public class JwtService {

    public String createJwtSymmetric() {
        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "HS256");
        headers.put("typ", "JWT");

        Map<String, Object> claims = new HashMap<>();
        claims.put("user_name", "jwryu");
        claims.put("scope", List.of("trust", "read", "write"));
        claims.put("client_id", "HT-IOAUTH");
        Map<String, Object> oauthUserInfo = new HashMap<>();
        oauthUserInfo.put("name", "jungwook");
        oauthUserInfo.put("memberId", "jwryu");
        claims.put("user_detail", Collections.singletonMap("oauth_user_info", oauthUserInfo));
        return Jwts.builder().setHeader(headers)
                .setClaims(claims)
                .setId(UUID.randomUUID().toString())
                .setExpiration(new Date(System.currentTimeMillis() + 86400000))
                .signWith(SignatureAlgorithm.HS256, "123".getBytes())
                .compact();
    }

    public String createJwtRSA1() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "HS256");
        headers.put("typ", "JWT");

        Map<String, Object> claims = new HashMap<>();
        claims.put("ver", "2.0");
        claims.put("memId", "jwryu");
        claims.put("siteId", "123");
        claims.put("dong", "101");
        claims.put("ho", "201");
        claims.put("scope", List.of("danji"));
        claims.put("authorities", List.of("user"));
        claims.put("client_id", "LGE");

        return Jwts.builder().setHeader(headers)
                .setClaims(claims)
                .setId(UUID.randomUUID().toString())
                .setExpiration(new Date(System.currentTimeMillis() + 86400000))
                .setIssuer("HT-IOAUTH")
                .signWith(SignatureAlgorithm.RS512, getPrivateKey("private_htioauth.der"))
                .compact();
    }

    public String createJwtRSA2() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "HS256");
        headers.put("typ", "JWT");

        Map<String, Object> claims = new HashMap<>();
        claims.put("ver", "2.0");
        claims.put("siteId", "123");
        claims.put("scope", List.of("danji"));
        claims.put("authorities", List.of("wallpad"));
        claims.put("client_id", "WALLPAD");

        return Jwts.builder().setHeader(headers)
                .setClaims(claims)
                .setId(UUID.randomUUID().toString())
                .setExpiration(new Date(System.currentTimeMillis() + 86400000))
                .setIssuer("OAUTH")
                .signWith(SignatureAlgorithm.RS512, getPrivateKey("private_oauth.der"))
                .compact();
    }

    private RSAPrivateKey getPrivateKey(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        InputStream is = getClass().getClassLoader().getResourceAsStream(filename);

        byte[] keyBytes = is.readAllBytes();

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(spec);

        is.close();
        return privateKey;
    }
}
