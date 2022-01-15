package llg.backend.service;

import llg.backend.domain.Role;
import llg.backend.domain.User;
import llg.backend.exception.InvalidRoleException;
import llg.backend.exception.UserAlreadyExistsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

public interface UserService {
    User saveUser(User user) throws UserAlreadyExistsException, InvalidRoleException;
    void deleteUser(User user);
    boolean checkIfEmailExists(String email);
    boolean checkIfUserNameExists(String username);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName) throws UsernameNotFoundException, InvalidRoleException;
    User getUser(String username);
    List<User> getUsers();
    boolean refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException;
    boolean changePassword(String username, String enteredOldPassword, String enteredNewPassword);
}
