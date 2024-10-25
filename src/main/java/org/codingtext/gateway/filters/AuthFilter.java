package org.codingtext.gateway.filters;

import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.codingtext.gateway.jwt.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class AuthFilter extends AbstractGatewayFilterFactory<AuthFilter.Config> {

    private final JwtProvider jwtProvider;

    @Autowired
    public AuthFilter(JwtProvider jwtProvider) {
        super(AuthFilter.Config.class);
        this.jwtProvider = jwtProvider;
    }

    public static class Config {
        // Config if needed
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String accessToken = jwtProvider.resolveTokenHeader(request);

            // JWT 검증
            if (jwtProvider.validateToken(accessToken)) {
                // 검증 성공, 요청을 계속 진행
                Claims claims = jwtProvider.getUserInfoFromToken(accessToken);
                String userId = claims.getSubject();
                request.mutate().header("UserId", userId).build(); //다른 MicroService 에서 해당 ID 참조 가능
                return chain.filter(exchange);
            }
            // 인증 실패 시 401 에러 반환
            log.info("게이트웨이에서 인증에 실패하였습니다.");
            return onError(exchange, "Unauthorized", HttpStatus.UNAUTHORIZED);
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus httpStatus) {
        exchange.getResponse().setStatusCode(httpStatus);
        log.error(message);
        return exchange.getResponse().setComplete();
    }
}