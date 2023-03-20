package Inflearn.security.jwt.config.jwt;

import Inflearn.security.jwt.config.auth.PrincipalDetails;
import Inflearn.security.jwt.model.User;
import Inflearn.security.jwt.repository.UserRepository;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// Security 가 Filter를 가지고 있는데 그 필터중에 BasicAuthenticationFilter 라는 것이 있는데
// 권한이나 인증이 필요한 특정 주소를 요쳥할 경우 위 필터를 필수로 거치게 함
// 만약 권한이 인증이 필요하지 않은 겨우 필터를 안탐
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    // 인증이나 권한이 필요한 주소요청이 있을때 해당 필터를 타게 됨
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
//        super.doFilterInternal(request, response, chain);
        System.out.println("인증이나 권한이 푤한 주수로 요청 됨");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader : " + jwtHeader);

        // JWT 토큰을 검증해서 정상적인 사용자인지 확인

        // header(Bearer ) 가 있는지
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
        String username = JWT.require(Algorithm.HMAC512("cos"))
                .build()
                .verify(jwtToken)
                .getClaim("username")
                .asString();

        // 서명이 정삭적이면
        if (username != null) {
            System.out.println("username 정상");
            User userEntity = userRepository.findByUsername(username);
            System.out.println("userEntity : " + userEntity);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            System.out.println("principalDetails : " + principalDetails);

            // JWT 토큰 서명을 통해 서명이 정삭이면 Authentication 객체를 만듬
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            // 강제로 시큐리티 세션에 접근하여 Authentication 객체를 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

        }
    }
}
