package com.auth.auth.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {


    @Getter
    @Value("${spring.security.jwt.key}")
    private String secretKey;

    @Getter
    private static final JWSAlgorithm algorithm = JWSAlgorithm.HS256;


    public SecretKey key () {
        return new SecretKeySpec(secretKey.getBytes(), JwtService.getAlgorithm().getName());
    }

    public String generateToken (String exp, Map<String, Object> claims) throws JOSEException {
        SignedJWT jwt = new SignedJWT(getHeader(), getClaims(getExp(exp), claims));
        MACSigner sing = new MACSigner(secretKey);
        jwt.sign(sing);
        return jwt.serialize();
    }


    private JWSHeader getHeader () {
        return new JWSHeader(algorithm);
    }

    private JWTClaimsSet getClaims (long exp, Map<String, Object> claims) {
        JWTClaimsSet.Builder claimBuilder = new JWTClaimsSet.Builder()
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(exp)));
        claims.forEach(claimBuilder::claim);
        return claimBuilder.build();
    }


    private long getExp(String exp) {
        long expiration = Long.parseLong(exp.replaceAll("[^0-9]", ""));
        if (exp.contains("s")) {
            return expiration;
        } else if (exp.contains("m")) {
            return expiration * 60;
        } else if (exp.contains("y")) {
            return expiration * 31536000;
        } else if (exp.contains("d")) {
            return expiration * 86400;
        }else throw new RuntimeException("unexpected value:" + exp);
    }


    public String extractToken (HttpServletRequest request) {
        return request.getHeader("Authorization").split(" ")[1];
    }


    private Jwt decodeToken (String token) {
        return NimbusJwtDecoder.withSecretKey(key()).build().decode(token);
    }


    public Map<String, Object> extractClaims (String token) {
        return decodeToken(token).getClaims();
    }






}
