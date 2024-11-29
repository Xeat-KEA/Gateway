package org.codingtext.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.slf4j.Slf4j;
import org.codingtext.gateway.error.ErrorResponse;
import org.codingtext.gateway.jwt.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;


@Component
@Slf4j
public class AuthAdminFilter extends AbstractGatewayFilterFactory<AuthAdminFilter.Config> {
    private final JwtProvider jwtProvider;

    @Autowired
    public AuthAdminFilter(JwtProvider jwtProvider) {
        super(AuthAdminFilter.Config.class);
        this.jwtProvider = jwtProvider;
    }

    public static class Config {
        // Config if needed
    }
    @Override
    public GatewayFilter apply(AuthAdminFilter.Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String accessToken = jwtProvider.resolveTokenHeader(request);

            try {
                // JWT 검증
                if (jwtProvider.validateToken(accessToken)) {
                    // 검증 성공, 요청을 계속 진행
                    Claims claims = jwtProvider.getUserInfoFromToken(accessToken);
                    String email = claims.getSubject();
                    request.mutate().header("Email", email).build(); // 다른 MicroService 에서 해당 ID 참조 가능
                    return chain.filter(exchange);
                }
            } catch (ExpiredJwtException e) {
                // 만료된 토큰의 경우 별도 처리
                return ErrorResponse.onError(exchange, "토큰이 만료되었습니다.", HttpStatus.PAYMENT_REQUIRED);
            }
            // 유효하지 않은 토큰의 경우 처리
            return ErrorResponse.onError(exchange, "AccessToken 이 유효하지 않습니다.", HttpStatus.UNAUTHORIZED);
        };
    }
}
