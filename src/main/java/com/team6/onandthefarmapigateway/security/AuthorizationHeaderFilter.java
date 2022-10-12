package com.team6.onandthefarmapigateway.security;

import com.team6.onandthefarmapigateway.vo.SellerResponse;
import com.team6.onandthefarmapigateway.vo.UserResponse;
import com.team6.onandthefarmapigateway.feignclient.MemberServiceClient;
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
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config>{

    private final MemberServiceClient memberServiceClient;
    private final JwtTokenUtil jwtTokenUtil;
    Environment env;
    private String adminKey;


    public AuthorizationHeaderFilter(MemberServiceClient memberServiceClient, JwtTokenUtil jwtTokenUtil, Environment env){
        this.memberServiceClient = memberServiceClient;
        this.jwtTokenUtil = jwtTokenUtil;
        this.env = env;
        this.adminKey = env.getProperty("jwt.admin-key");
    }

    public static class Config{

    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
                return setErrorResponse(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
            }
            
            String accessToken = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);

            if(accessToken != null) {

                try{
//                    if(!isJwtValid(accessToken)){
//                        return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
//                    }

                    String role = jwtTokenUtil.getRole(accessToken);
                    if(role.equals("ROLE_ADMIN")){
                        Long sellerId = jwtTokenUtil.getId(accessToken);
                        System.out.println("jwt 인증 필터에서 토큰 속 셀러 정보 : "+ sellerId);

                        if(sellerId == null){
                            throw new IllegalArgumentException("정보가 담겨있지 않은 빈 토큰입니다.");
                        }
                        // 3. Access Token 토큰에 포함된 유저 정보를 통해 실제 DB에 해당 정보의 계정이 있는지 조회
                        SellerResponse seller = memberServiceClient.findBySellerId(sellerId);
                        if (seller != null) {
                            //System.out.println("DB에서 가져온 사용자 정보 : "+user.getUserId()+" "+user.getUserEmail());

                            // 4. 토큰 유효성 검증
                            if (jwtTokenUtil.validateToken(accessToken)) {

                                // 4-1. 식별된 정상 유저인 경우, 요청 context 내에서 참조 가능한 인증 정보(jwtAuthentication) 생성
//                            UsernamePasswordAuthenticationToken jwtAuthentication = new UsernamePasswordAuthenticationToken(sellerId,
//                                    sellerId + adminKey, AuthorityUtils.createAuthorityList(seller.getRole()));

                                // 4-2. jwt 토큰으로 부터 획득한 인증 정보(authentication) 설정
//                            SecurityContextHolder.getContext().setAuthentication(jwtAuthentication);

                                // Authentication이 아닌 헤더에 유저 정보를 담아서 보내기
                                request.getHeaders().set("memberId", Long.toString(sellerId));
                                request.getHeaders().set("memberRole", "seller");
                            }
                        }
                        else {    // DB에 해당 유저 없는 경우
                            throw new NullPointerException("존재하지 않는 유저입니다.");
                        }
                    }
                    else{
                        Long userId = jwtTokenUtil.getId(accessToken);
                        System.out.println("jwt 인증 필터에서 토큰 속 사용자 정보 : "+userId);

                        if (userId == null) {
                            throw new IllegalArgumentException("정보가 담겨있지 않은 빈 토큰입니다.");
                        }

                        // 3. Access Token 토큰에 포함된 유저 정보를 통해 실제 DB에 해당 정보의 계정이 있는지 조회
                        UserResponse user = memberServiceClient.findByUserId(userId);
                        if (user != null) {
                            //System.out.println("DB에서 가져온 사용자 정보 : "+user.getUserId()+" "+user.getUserEmail());

                            // 4. 토큰 유효성 검증
                            if (jwtTokenUtil.validateToken(accessToken)) {

                                // 4-1. 식별된 정상 유저인 경우, 요청 context 내에서 참조 가능한 인증 정보(jwtAuthentication) 생성
//                            UsernamePasswordAuthenticationToken jwtAuthentication = new UsernamePasswordAuthenticationToken(userId,
//                                    userId + adminKey, AuthorityUtils.createAuthorityList(user.getRole()));
//
//                            // 4-2. jwt 토큰으로 부터 획득한 인증 정보(authentication) 설정
//                            SecurityContextHolder.getContext().setAuthentication(jwtAuthentication);

                                // Authentication이 아닌 헤더에 유저 정보를 담아서 보내기
                                request.getHeaders().set("memberId", Long.toString(userId));
                                request.getHeaders().set("memberRole", "user");
                            }
                        }
                        else {    // DB에 해당 유저 없는 경우
                            throw new NullPointerException("존재하지 않는 유저입니다.");
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

            return chain.filter(exchange);
        });
    }

//    private boolean isJwtValid(String jwt) {
//        boolean isValid = true;
//
//        String subject = null;
//
//        try {
//            subject = Jwts.parserBuilder().setSigningKey(env.getProperty("jwt.secret")).build()
//                    .parseClaimsJws(jwt).getBody()
//                    .getSubject();
//        }
//        catch (Exception ex){
//            isValid = false;
//        }
//
//        if(subject == null || subject.isEmpty()){
//            isValid = false;
//        }
//
//        return isValid;
//    }

    private Mono<Void> setErrorResponse(ServerWebExchange exchange, String message, HttpStatus httpStatus) {

        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        log.error(message);
        return response.setComplete();
    }

}
