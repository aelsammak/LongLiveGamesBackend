package llg.backend.controller;

import llg.backend.domain.User;
import llg.backend.exception.InvalidRoleException;
import llg.backend.exception.UserAlreadyExistsException;
import llg.backend.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;
import java.net.URI;
import java.util.*;

@RestController
@RequestMapping("/api/v0/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;

    @GetMapping("")
    public List<User> all() {
        return userService.getUsers();
    }

    @GetMapping("/{username}")
    public ResponseEntity<?> get(@PathVariable("username") String username) {
        User user = userService.getUser(username);
        if (user != null) {
            return ResponseEntity.ok().body(user);
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("no user found with username: " + username);
        }
    }

    @PutMapping("/{username}")
    public ResponseEntity<?> changePassword(@PathVariable("username") String username,
                                            @RequestBody Map<String, String> userPasswords) {
        try {
            if (userService.changePassword(username, userPasswords.get("oldPassword"), userPasswords.get("newPassword"))) {
                return ResponseEntity.ok().body("password has been successfully updated");
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("old password is incorrect");
            }
        } catch (UsernameNotFoundException unfe) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(unfe.getMessage());
        }
    }

    @PostMapping("")
    public ResponseEntity<?> create(@Valid @RequestBody User user) {
        try {
            userService.saveUser(user);
        } catch (UserAlreadyExistsException | InvalidRoleException uaee){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(uaee.getMessage());
        }
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/v0/users/").toUriString());
        return ResponseEntity.created(uri).body(user);
    }

    @PutMapping("/{username}/roles/{roleName}")
    public ResponseEntity<?> update(@PathVariable("username") String username, @PathVariable("roleName") String roleName) {
        try {
            userService.addRoleToUser(username, roleName);
        } catch (Exception e) {
            if (e instanceof UsernameNotFoundException) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
            } else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
            }
        }
        return ResponseEntity.status(HttpStatus.OK).body("Role: " + roleName + " has been added to user: " + username);
    }

    @DeleteMapping("/{username}")
    public void delete(@PathVariable("username") String username) {
        User user = userService.getUser(username);
        if (user != null) {
            userService.deleteUser(user);
        }
    }

    @PostMapping("/refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!(userService.refreshToken(request, response))) {
            throw new RuntimeException("Refresh Token is missing");
        }
    }

    /* Exception Handler */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public Map<String, String> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        return errors;
    }
}
