package llg.backend.utility;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import llg.backend.domain.Role;
import llg.backend.service.UserService;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@UtilityClass
@Slf4j
public class TokenUtility {

    private final Algorithm algorithm = Algorithm.HMAC256("SECRET".getBytes()); // TODO NEED TO ENCRYPT SECRET

    public void createAccessToken(String username, List<String> roles, HttpServletRequest request, Map<String, String> tokens) {
        String access_token = JWT.create()
                .withSubject(username)
                .withExpiresAt(new Date(System.currentTimeMillis() + (long) (3.154 *  Math.pow(10, 10))))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", roles)
                .sign(algorithm);

        tokens.put("username", username);
        tokens.put("access_token", access_token);
    }

    public void createRefreshToken(User user, HttpServletRequest request, Map<String, String> tokens) {
        String refresh_token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + (long) (5.184 *  Math.pow(10, 9))))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);

        tokens.put("refresh_token", refresh_token);
    }

    public void authenticateToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            DecodedJWT decodedJWT = getDecodedToken(request, response, false, null);
            String username = getUsernameFromToken(decodedJWT);
            String[] roles = getRolesFromToken(decodedJWT);
            Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
            stream(roles).forEach(role -> {
                authorities.add(new SimpleGrantedAuthority(role));
            });
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        } catch (Exception e) {
            errorMsg(response, e);
        }
    }

    public DecodedJWT getDecodedToken(HttpServletRequest request, HttpServletResponse response, boolean isRefreshToken, Map<String, String> tokens) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                String token = authorizationHeader.substring("Bearer ".length());
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(token);
                if (isRefreshToken) {
                    tokens.put("refresh_token", token);
                }
                return decodedJWT;
            } catch (Exception e) {
                errorMsg(response, e);
            }
        }
        return null;
    }

    public String getUsernameFromToken(DecodedJWT decodedJWT) {
        return decodedJWT.getSubject();
    }

    public String[] getRolesFromToken(DecodedJWT decodedJWT) {
        return decodedJWT.getClaim("roles").asArray(String.class);
    }

    public boolean refreshToken(HttpServletRequest request, HttpServletResponse response, UserService userService) throws IOException {
        try {
            Map<String, String> tokens = new HashMap<>();
            DecodedJWT decodedJWT = getDecodedToken(request, response, true, tokens);
            String username = getUsernameFromToken(decodedJWT);
            llg.backend.domain.User user = userService.getUser(username);
            createAccessToken(username, user.getRoles().stream().map(Role::getName).collect(Collectors.toList()), request, tokens);
            response.setContentType("application/json");
            new ObjectMapper().writeValue(response.getOutputStream(), tokens);
            return true;
        } catch (Exception e) {
            errorMsg(response, e);
            return false;
        }
    }

    public void getUserFromToken(HttpServletRequest request, HttpServletResponse response, UserService userService) throws IOException {
            try {
                DecodedJWT decodedJWT = getDecodedToken(request, response, false, null);
                String username = getUsernameFromToken(decodedJWT);
                llg.backend.domain.User user = userService.getUser(username);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(), user);
            } catch (Exception e) {
                errorMsg(response, e);
            }
        }

    public static void errorMsg(HttpServletResponse response, Exception e) throws IOException {
        log.error("Error logging in: {}", e.getMessage());
        response.setHeader("error", e.getMessage());
        response.setStatus(FORBIDDEN.value());
        Map<String, String> error = new HashMap<>();
        error.put("error_msg", e.getMessage());
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), error);
    }
}
