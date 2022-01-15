package llg.backend.controller;

import llg.backend.constants.ROLES;
import llg.backend.domain.Role;
import llg.backend.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;

@RestController
@RequestMapping("/api/v0/roles")
@RequiredArgsConstructor
public class RoleController {

    private final UserService userService;

    @PostMapping("/{roleName}")
    public ResponseEntity<?> create(@PathVariable("roleName") String roleName) {
        if (roleName.equals(ROLES.ROLE_USER.toString()) || roleName.equals(ROLES.ROLE_ADMIN.toString())) {
            Role role = new Role(null, roleName);
            URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/v0/roles/").toUriString());
            return ResponseEntity.created(uri).body(userService.saveRole(role));
        } else {
            return ResponseEntity.badRequest().body("Valid Roles are only: " + ROLES.ROLE_USER.toString() + " AND " + ROLES.ROLE_ADMIN.toString());
        }
    }
}
