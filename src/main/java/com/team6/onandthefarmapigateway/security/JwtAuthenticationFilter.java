package com.team6.onandthefarmapigateway.security;

import com.team6.onandthefarmapigateway.vo.SellerResponse;
import com.team6.onandthefarmapigateway.vo.UserResponse;
import com.team6.onandthefarmapigateway.feignclient.MemberServiceClient;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import java.io.IOException;
import java.util.List;

@Slf4j
@Component
public class JwtAuthenticationFilter {

    //private final UserService userService;
//    private final UserRepository userRepository;
//    private final SellerRepository sellerRepository;

    private final MemberServiceClient memberServiceClient;
    private final JwtTokenUtil jwtTokenUtil;

    private String adminKey = "4e2945af65919af52b418b54f26f26c2";

    @Autowired
    public JwtAuthenticationFilter(MemberServiceClient memberServiceClient, JwtTokenUtil jwtTokenUtil) {
        //this.userService = userService;
//        this.userRepository = userRepository;
//        this.sellerRepository = sellerRepository;
        this.memberServiceClient = memberServiceClient;
        this.jwtTokenUtil = jwtTokenUtil;
    }

    //@Override
    protected void doFilterInternal(ServerWebExchange exchange, GatewayFilterChain filterChain) throws IOException {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();
        List<String> accessTokens = request.getHeaders().get("Authorization");
        String accessToken = accessTokens.get(0);

        if (accessToken != null) {
            // 1. Access Token이 이미 재발급 되어서 redis에 블랙리스트로 들어가있는지 확인
//            String inBlackList = redisUtil.getData(accessToken.replace(jwtTokenUtil.TOKEN_PREFIX, ""));
//            if (inBlackList != null && inBlackList.equals("B")) {
//                throw new SecurityException("사용할 수 없는 토큰입니다.");
//            }
            try {
                // 2. Access Token에서 사용자 정보 추출
                if (accessToken == null || accessToken.isEmpty()) {
                    throw new IllegalArgumentException("토큰이 존재하지 않습니다");
                }

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
                        }
                    }
                    else {    // DB에 해당 유저 없는 경우
                        throw new NullPointerException("존재하지 않는 유저입니다.");
                    }
                }
            } catch (SignatureException ex) {
                throw new SignatureException("유효하지 않은 JWT 서명입니다.");
            } catch (MalformedJwtException ex) {
                throw new MalformedJwtException("올바르지 않은 JWT 토큰입니다.");
            } catch (ExpiredJwtException ex) {
                throw new NullPointerException("만료된 JWT 토큰입니다.");
            } catch (UnsupportedJwtException ex) {
                throw new UnsupportedJwtException("지원하지 않는 형식의 JWT 토큰입니다.");
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("정보가 담겨있지 않은 빈 토큰입니다.");
            } catch (Exception ex) {
                log.error("올바르지 않은 JWT 토큰입니다. - Exception");
            }
        }
        //filterChain.doFilter(request, response);
    }
}
