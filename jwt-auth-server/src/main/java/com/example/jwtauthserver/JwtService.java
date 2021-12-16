package com.example.jwtauthserver;

import io.jsonwebtoken.JwtBuilder;
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
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {
    public String createJwtSymmetric() {
        String token = JwtBuilder()
                .signWith(SignatureAlgorithm.HS512, "token_secret")
                .compact();
        return token;
    }

    public String createJwtRSA() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String token = JwtBuilder()
                .signWith(SignatureAlgorithm.RS512, getPrivateKey("private.der"))
                .compact();
        return token;
    }

    public Map<String, Object> checkJwtRSA() {
        return null;
    }

    private JwtBuilder JwtBuilder() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("ver", "2.0");

        return Jwts.builder()
                .setSubject("jungwook")
                .setId("id")
                .setAudience("audience")
                .setIssuer("issuer")
                .addClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + 8640000));
    }

    private RSAPrivateKey getPrivateKey(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        InputStream is = getClass().getClassLoader().getResourceAsStream(filename);

        byte[] keyBytes = is.readAllBytes();

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(spec);

        return privateKey;
    }
}
