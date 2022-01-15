package llg.backend.config;

import llg.backend.constants.ROLES;
import llg.backend.filter.CustomAuthenticationFilter;
import llg.backend.filter.CustomAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;


import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean());
        customAuthenticationFilter.setFilterProcessesUrl("/api/v0/login");
        http.csrf().disable();
        http.cors();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests().antMatchers(HttpMethod.OPTIONS).permitAll();
        http.authorizeRequests().antMatchers(HttpMethod.HEAD).permitAll();
        http.authorizeRequests().antMatchers(HttpMethod.POST,"/api/v0/login", "/api/v0/users", "/api/v0/users/refresh-token").permitAll();
        http.authorizeRequests().antMatchers(HttpMethod.POST,"/api/v0/roles/**").hasAuthority(ROLES.ROLE_ADMIN.toString());
        http.authorizeRequests().antMatchers(HttpMethod.GET, "/api/v0/users").hasAuthority(ROLES.ROLE_ADMIN.toString());
        http.authorizeRequests().antMatchers(HttpMethod.POST, "/api/v0/users/**").hasAuthority(ROLES.ROLE_ADMIN.toString());
        http.authorizeRequests().antMatchers(HttpMethod.PUT, "/api/v0/users/**").hasAuthority(ROLES.ROLE_USER.toString());
        http.authorizeRequests().antMatchers(HttpMethod.GET, "/api/v0/users/**").hasAuthority(ROLES.ROLE_USER.toString());
        http.authorizeRequests().antMatchers(HttpMethod.PUT, "/api/v0/users/**").hasAuthority(ROLES.ROLE_ADMIN.toString());
        http.authorizeRequests().antMatchers(HttpMethod.PATCH, "/api/v0/users/**").hasAuthority(ROLES.ROLE_USER.toString());
        http.authorizeRequests().antMatchers(HttpMethod.DELETE, "/api/v0/users/**").hasAuthority(ROLES.ROLE_ADMIN.toString());
        http.authorizeRequests().anyRequest().authenticated();
        http.addFilter(customAuthenticationFilter);
        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
        return source;
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
