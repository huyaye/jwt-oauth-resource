package com.example.jwtauthserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@RestController
public class JwtController {
    @Autowired
    private JwtService jwtService;

    @GetMapping("/symmetric")
    public ResponseEntity<String> getJwtBySymmetric() {
        String jwt = jwtService.createJwtSymmetric();
        return new ResponseEntity<>(jwt, HttpStatus.CREATED);
    }

    @GetMapping("/rsa")
    public ResponseEntity<String> getJwtByASymmetric1() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String jwt = jwtService.createJwtRSA();
        return new ResponseEntity<>(jwt, HttpStatus.CREATED);
    }
}
