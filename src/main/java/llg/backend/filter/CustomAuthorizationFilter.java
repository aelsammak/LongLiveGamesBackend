package llg.backend.filter;

import llg.backend.utility.TokenUtility;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!request.getServletPath().equals("/api/v0/login") && !request.getServletPath().equals("/api/v0/users/refresh-token") && !request.getServletPath().equals("/api/v0/users")) {
            TokenUtility.authenticateToken(request, response);
        }
        filterChain.doFilter(request, response);
    }
}
