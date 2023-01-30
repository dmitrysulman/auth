package com.dmitrysulman.auth.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.ZonedDateTime;
import java.util.Date;

@Service
public class JwtService {
    private final JWKSource<SecurityContext> jwkSource;

    @Autowired
    public JwtService(JWKSource<SecurityContext> jwkSource) {
        this.jwkSource = jwkSource;
    }

    public String generateToken(String username) {
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(username)
                .issuer("auth")
                .expirationTime(Date.from(ZonedDateTime.now().plusMinutes(60).toInstant()))
                .build();
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
        SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);

        JWKMatcher jwkMatcher = new JWKMatcher.Builder().build();
        JWKSelector jwkSelector = new JWKSelector(jwkMatcher);
        try {
            RSAKey rsaKey = (RSAKey) jwkSource.get(jwkSelector, null).get(0);
            JWSSigner jwsSigner = new RSASSASigner(rsaKey);
            signedJWT.sign(jwsSigner);

            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }


}
