package org.codingtext.gateway.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAdminProvider {

    @Value("${jwt.admin.secret}")
    private String adminSecret;
    private SecretKey adminSecretKey;

    @PostConstruct
    public void init() {
        adminSecretKey = new SecretKeySpec(adminSecret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    //Authorization: JWT 검증
    public String resolveAdminTokenHeader(ServerHttpRequest request) {
        String bearerToken = request.getHeaders().getFirst("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public boolean validateAdminToken(String token) {
        try {
            Jwts
                    .parser()
                    .verifyWith(adminSecretKey)
                    .build()
                    .parseSignedClaims(token);
            return true;

        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token. 만료된 jwt 토큰 입니다.");
            throw e; // 만료된 토큰의 경우 별도로 처리하기 위해 예외를 던집니다.
        } catch (SignatureException e) {
            log.error("Invalid JWT signature, signature 가 유효하지 않은 토큰 입니다.");
        } catch (MalformedJwtException | UnsupportedJwtException e) {
            log.error("Invalid JWT token, 유효하지 않은 jwt 토큰 입니다.");
        } catch (IllegalArgumentException e) {
            log.error("JWT claims is empty, 잘못된 JWT 토큰 입니다.");
        }
        return false;
    }

    public Claims getUserInfoFromAdminToken(String token) {
        return Jwts
                .parser()
                .verifyWith(adminSecretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}