package com.team6.onandthefarmapigateway.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Slf4j
@Component
public class JwtTokenUtil {

    private final Key secretKey;

    public static final String TOKEN_PREFIX = "Bearer ";

    Environment env;


    @Autowired
    public JwtTokenUtil(Environment env) {
        this.env = env;

        String secretKey = env.getProperty("jwt.secret");

        // secretKey 바이트로 변환하여 Base64로 인코딩
        String encodingSecretKey = Base64.getEncoder().encodeToString(secretKey.getBytes(StandardCharsets.UTF_8));
        // Base64 byte[]로 변환
        byte[] decodedByte = Base64.getDecoder().decode(encodingSecretKey.getBytes(StandardCharsets.UTF_8));
        // byte[]로 key 생성
        this.secretKey = Keys.hmacShaKeyFor(decodedByte);
    }

    public Token generateToken(Long id, String role) {
        long tokenPeriod = 1000L * 60L * 1440L; //5분
        long refreshPeriod = 1000L * 60L * 60L * 24L * 30L * 3L;

        Claims claims = Jwts.claims();
        claims.put("role", role);
        claims.put("id", id);

        Date now = new Date();
        return new Token(
                Jwts.builder()
                        .setSubject("Access Token")
                        //.claim("userId", userId)
                        .setClaims(claims)
                        .setIssuedAt(now)
                        .setExpiration(new Date(now.getTime() + tokenPeriod))
                        .signWith(secretKey, SignatureAlgorithm.HS512)
                        .compact(),
                Jwts.builder()
                        .setSubject("Refresh Token")
                        .setIssuedAt(now)
                        .setExpiration(new Date(now.getTime() + refreshPeriod))
                        .signWith(secretKey, SignatureAlgorithm.HS512)
                        .compact());
    }

    // 토큰에 담긴 payload 값 가져오기
    public Claims extractAllClaims(String token) throws ExpiredJwtException {
        String tokenDelPrefix = token.replace(TOKEN_PREFIX, "");
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(tokenDelPrefix)
                .getBody();
    }

    //토큰 만료되었는지 확인
    public boolean checkExpiredToken(String token) {
        final Date expiration = extractAllClaims(token).getExpiration();
        return expiration.before(new Date());
    }

    //UserId 가져오기
    public Long getId(String token) {
        return extractAllClaims(token).get("id", Long.class);
    }

    public String getRole(String token){
        return extractAllClaims(token).get("role", String.class);
    }

    public Boolean validateToken(String token) {
        String tokenDelPrefix = token.replace(TOKEN_PREFIX, "");

        try {
            Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(tokenDelPrefix);
            return true;
        } catch (SignatureException ex) {
            log.error("validateToken - 유효하지 않은 JWT 서명입니다.");
            throw new SignatureException("유효하지 않은 JWT 서명입니다.");
        } catch (MalformedJwtException ex) {
            log.error("validateToken - 올바르지 않은 JWT 토큰입니다.");
            throw new MalformedJwtException("올바르지 않은 JWT 토큰입니다.");
        } catch (ExpiredJwtException ex) {
            log.error("validateToken - 만료된 JWT 토큰입니다.");
            throw new NullPointerException("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException ex) {
            log.error("validateToken - 지원하지 않는 형식의 JWT 토큰입니다.");
            throw new UnsupportedJwtException("지원하지 않는 형식의 JWT 토큰입니다.");
        } catch (IllegalArgumentException ex) {
            log.error("validateToken - 정보가 담겨있지 않은 빈 토큰입니다.");
            throw new IllegalArgumentException("정보가 담겨있지 않은 빈 토큰입니다.");
        }
    }
}
