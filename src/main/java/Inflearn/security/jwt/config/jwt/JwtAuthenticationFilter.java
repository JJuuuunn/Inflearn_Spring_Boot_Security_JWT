package Inflearn.security.jwt.config.jwt;

import Inflearn.security.jwt.config.auth.PrincipalDetails;
import Inflearn.security.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;

/**
 * Spring Security 에서 UsernamePasswordAuthenticationFilter 가 존재함
 * /login 요청 시 username, password 전송(post)하면
 * UsernamePasswordAuthenticationFilter 동작
 * But SecurityConfig 에서 .formLogin().disable() 로 설정하여서 동작안함
 * So JwtAuthenticationFilter 를 SecurityConfig 에
 * .addFilter(new JwtAuthenticationFilter()) 로 설정하여 동작시킴
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청시 로그인 시도를 위해 실행하는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도중");

        // 1. username, password 를 받아서
        try {
//            BufferedReader br = request.getReader();
//
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                System.out.println(input);
//            }
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService 의 loadUerByUsername() 함수가 실행, 정싱이면 authentication 이 리턴
            // DB 에 있는 username 과 password 가 일치
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // => 로그인 되었다는 뜻
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료(username) : " + principalDetails.getUser().getUsername()); // 로그인이 정상적으로 실행
            System.out.println("1=====================================");

            // authentication 객체가 session영역에 저장을 해야하고 그 방법이 return
            // 리턴 하는 이유는 권한 관리를 security가 대신 해주기 때문에 편할려고
            // 굳이 JWT토큰을 사용하면서 세션을 만들 이유가 없음, 단지 권한처리 때문에 session에 넣음
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("2=====================================");

        // 2. 정상인지 로그인 시도를 해보기,
        // authenticationManager 로 로그인 시도를 하면 PrincipalDetails 로 호출되고 loadUserByUsername() 함수가 실행

        // 3. PrincipalDetails 를 세션에 담고 (권한 관리를 위해)

        // 4. JWT 토큰 을 만들어 응담


        return null;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되면 successfulAuthentication 함수 실행
    // JWT 토큰을 만들어 request 요쳥한 사용자에게 JWT 토큰 response
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        System.out.println("successfulAuthentication 실행됨 : 인증 완료");
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
