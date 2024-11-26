package org.codingtext.gateway.filter;

import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.codingtext.gateway.jwt.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

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

            // JWT 검증
            if (jwtProvider.validateToken(accessToken)) {
                // 검증 성공, 요청을 계속 진행
                Claims claims = jwtProvider.getUserInfoFromToken(accessToken);
                String adminId = claims.getSubject();
                request.mutate().header("AdminId", adminId).build();
                return chain.filter(exchange);
            }
            // 인증 실패 시 401 에러 반환
            return onError(exchange, "AccessToken 이 유효하지 않습니다.", HttpStatus.UNAUTHORIZED);
        };
    }


    // 오류 처리 메서드
    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus httpStatus) {
        exchange.getResponse().setStatusCode(httpStatus);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // JSON 응답 생성
        String jsonResponse = String.format("{\"message\":\"%s\",\"status\":%d}", message, httpStatus.value());

        // 응답 작성
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(jsonResponse.getBytes())));
    }
}
