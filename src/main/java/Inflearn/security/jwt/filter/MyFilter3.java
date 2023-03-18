package Inflearn.security.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // 'cos' 라는 이름을 가진 토큰을 만들었다는 가정하에 들어오면 인증
        // 아니면 필터를 못타게하여 controller 에 진입을 못하게끔 만듬
        // 'cox' 라는 토큰을 만들어줘야함 -> id, pw가 정상적으로 들어와 로그인 완료되면 토큰을 만들어 응답(res)한다.
        // 요청할 때 마다 header에 Authorization 에 Value 값으로 토큰을 가져오니
        // 그떄 토큰이 내가 만든 토큰인지 검즘하면 됨 (RSA, HS256)
        if (req.getMethod().equals("POST")) {
            System.out.println("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);
            System.out.println("필터 3");

            if (headerAuth.equals("cos")) {
                chain.doFilter(req, res);
            } else {
                PrintWriter out = res.getWriter();
                out.println("인증 안됨");
            }
        }

    }
}
