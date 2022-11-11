package com.team6.onandthefarmapigateway.security;

import com.team6.onandthefarmapigateway.redis.RedisUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class EitherAuthorizationHeaderFilter extends AbstractGatewayFilterFactory<EitherAuthorizationHeaderFilter.Config> {

    private final JwtTokenUtil jwtTokenUtil;
    private final RedisUtil redisUtil;
    Environment env;


    public EitherAuthorizationHeaderFilter(RedisUtil redisUtil,
                                     JwtTokenUtil jwtTokenUtil,
                                     Environment env){
        super(EitherAuthorizationHeaderFilter.Config.class);

        this.redisUtil = redisUtil;
        this.jwtTokenUtil = jwtTokenUtil;
        this.env = env;
    }

    public static class Config {
        // Put configuration properties here
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            ServerWebExchange serverWebExchange = null;
            if(request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
                String accessToken = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);

                if(accessToken != null) {
                    // 1. Access Token이 이미 재발급 되어서 redis에 블랙리스트로 들어가있는지 확인
                    String inBlackList = redisUtil.getValues(accessToken);
                    if (inBlackList != null && inBlackList.equals("BlackList")) {
                        throw new SecurityException("사용할 수 없는 토큰입니다.");
                    }

                    try{
                        String role = jwtTokenUtil.getRole(accessToken);
                        if(role.equals("ROLE_SELLER")){
                            Long sellerId = jwtTokenUtil.getId(accessToken);
                            System.out.println("jwt 인증 필터에서 토큰 속 셀러 정보 : "+ sellerId);

                            if(sellerId == null){
                                throw new IllegalArgumentException("정보가 담겨있지 않은 빈 토큰입니다.");
                            }

                            // 4. 토큰 유효성 검증
                            if (jwtTokenUtil.validateToken(accessToken)) {
                                // Authentication이 아닌 헤더에 유저 정보를 담아서 보내기
                                ServerHttpRequest newRequest = request.mutate()
                                        .header("memberId", Long.toString(sellerId))
                                        .header("memberRole", "seller").build();

                                serverWebExchange = exchange.mutate().request(newRequest).build();
                            }
                        }
                        else if(role.equals("ROLE_USER")){
                            Long userId = jwtTokenUtil.getId(accessToken);
                            System.out.println("jwt 인증 필터에서 토큰 속 사용자 정보 : "+userId);

                            if (userId == null) {
                                throw new IllegalArgumentException("정보가 담겨있지 않은 빈 토큰입니다.");
                            }

                            // 4. 토큰 유효성 검증
                            if (jwtTokenUtil.validateToken(accessToken)) {
                                // Authentication이 아닌 헤더에 유저 정보를 담아서 보내기
                                ServerHttpRequest newRequest = request.mutate()
                                        .header("memberId", Long.toString(userId))
                                        .header("memberRole", "user").build();

                                serverWebExchange = exchange.mutate().request(newRequest).build();
                            }
                        }
                        else{
                            Long adminId = jwtTokenUtil.getId(accessToken);
                            System.out.println("jwt 인증 필터에서 토큰 속 관리자 정보 : "+adminId);

                            if (adminId == null) {
                                throw new IllegalArgumentException("정보가 담겨있지 않은 빈 토큰입니다.");
                            }

                            // 4. 토큰 유효성 검증
                            if (jwtTokenUtil.validateToken(accessToken)) {
                                // Authentication이 아닌 헤더에 유저 정보를 담아서 보내기
                                ServerHttpRequest newRequest = request.mutate()
                                        .header("memberId", Long.toString(adminId))
                                        .header("memberRole", "admin").build();

                                serverWebExchange = exchange.mutate().request(newRequest).build();
                            }
                        }
                    }
                    catch (SignatureException ex) {
                        log.error("AuthorizationHeaderFilter - 유효하지 않은 JWT 서명입니다.");
                        throw new SignatureException("유효하지 않은 JWT 서명입니다.");
                    } catch (MalformedJwtException ex) {
                        log.error("AuthorizationHeaderFilter - 올바르지 않은 JWT 토큰입니다.");
                        throw new MalformedJwtException("올바르지 않은 JWT 토큰입니다.");
                    } catch (ExpiredJwtException ex) {
                        log.error("AuthorizationHeaderFilter - 만료된 JWT 토큰입니다.");
                        throw new NullPointerException("만료된 JWT 토큰입니다.");
                    } catch (UnsupportedJwtException ex) {
                        log.error("AuthorizationHeaderFilter - 지원하지 않는 형식의 JWT 토큰입니다.");
                        throw new UnsupportedJwtException("지원하지 않는 형식의 JWT 토큰입니다.");
                    } catch (IllegalArgumentException ex) {
                        log.error("AuthorizationHeaderFilter - 정보가 담겨있지 않은 빈 토큰입니다.");
                        throw new IllegalArgumentException("정보가 담겨있지 않은 빈 토큰입니다.");
                    } catch (Exception ex) {
                        log.error("AuthorizationHeaderFilter - 올바르지 않은 JWT 토큰입니다.");
                    }
                }
                return chain.filter(serverWebExchange);
            }
            return chain.filter(exchange.mutate().build());
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus httpStatus) {

        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        log.error(message);
        return response.setComplete();
    }

}
