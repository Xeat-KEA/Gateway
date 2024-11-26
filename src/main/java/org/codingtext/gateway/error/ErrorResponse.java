package org.codingtext.gateway.error;


import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class ErrorResponse {
    private ErrorResponse() {
        // 유틸리티 클래스는 인스턴스화 방지
    }
    // 오류 처리 메서드
    public static Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus httpStatus) {
        exchange.getResponse().setStatusCode(httpStatus);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // JSON 응답 생성
        String jsonResponse = String.format("{\"message\":\"%s\",\"status\":%d}", message, httpStatus.value());

        // 응답 작성
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(jsonResponse.getBytes())));
    }
}
