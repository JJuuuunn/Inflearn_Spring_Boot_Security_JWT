package Inflearn.security.jwt.config;

import Inflearn.security.jwt.config.jwt.JwtAuthenticationFilter;
import Inflearn.security.jwt.filter.MyFilter3;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;

    // Password Encoding 메소드
    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
        http.csrf().disable(); // 토큰 사용 방식을 위해 csrf 비활성화
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // (STATELESS) 세션을 사용하지 않게 설정
                .and()
                .addFilter(corsFilter) // @CrossOrigin(인증X), 시큐리티 필터에 등록 인증(O)
                .formLogin().disable()
                .httpBasic().disable()
                .authorizeRequests()
                .antMatchers("/api/v1/user/**").access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**").access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
        ;
    }
}
