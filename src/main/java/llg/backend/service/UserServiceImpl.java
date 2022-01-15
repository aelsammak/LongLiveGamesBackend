package llg.backend.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import llg.backend.constants.ROLES;
import llg.backend.domain.Role;
import llg.backend.domain.User;
import llg.backend.exception.InvalidRoleException;
import llg.backend.exception.UserAlreadyExistsException;
import llg.backend.repository.RoleRepo;
import llg.backend.repository.UserRepo;
import llg.backend.utility.TokenUtility;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.transaction.Transactional;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepo userRepo;
    private final RoleRepo roleRepo;

    @Autowired
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public User saveUser(User user) throws UserAlreadyExistsException, InvalidRoleException {
        if(checkIfUserNameExists(user.getUsername())) {
            throw new UserAlreadyExistsException("username already exists");
        } else if (checkIfEmailExists(user.getEmail())) {
            throw new UserAlreadyExistsException("email already exists");
        }
        user.setPassword(passwordEncoder().encode(user.getPassword()));
        log.info(user.getUsername() + " has been saved");
        User savedUser = userRepo.save(user);
        this.addRoleToUser(savedUser.getUsername(), ROLES.ROLE_USER.toString());
        return savedUser;
    }

    @Override
    public boolean checkIfEmailExists(String email) {
        return userRepo.findByEmail(email) != null;
    }

    @Override
    public boolean checkIfUserNameExists(String username) {
        return userRepo.findByUsername(username) != null;
    }

    @Override
    public Role saveRole(Role role) {
        return roleRepo.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) throws UsernameNotFoundException, InvalidRoleException {
        User user = userRepo.findByUsername(username);
        Role role = roleRepo.findByName(roleName);
        if (user != null && role != null) {
            user.getRoles().add(role);
            log.info(role.getName() + " has been added to " + user.getUsername());
        } else if (user == null) {
            throw new UsernameNotFoundException("User not found with username: " + username);
        } else {
            throw new InvalidRoleException("Invalid Role name: " + roleName +
                    " Valid Role names: " + ROLES.ROLE_USER.toString() + " AND " + ROLES.ROLE_ADMIN.toString());
        }
    }

   @Override
   public void deleteUser(User user) {
        log.info("Deleting user " + user.getUsername());
        userRepo.delete(user);
   }

    @Override
    public User getUser(String username) {
        log.info("Fetching user " + username);
        return userRepo.findByUsername(username);
    }

    @Override
    public List<User> getUsers() {
        log.info("Fetching all users");
        return userRepo.findAll();
    }

    @Override
    public boolean refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        return TokenUtility.refreshToken(request, response, this);
    }

    @Override
    public boolean changePassword(String username, String enteredOldPassword, String enteredNewPassword) {
        User user = this.getUser(username);
        if (user == null) {
            throw new UsernameNotFoundException("user not found");
        }
        if (passwordEncoder().matches(enteredOldPassword,user.getPassword())) {
            user.setPassword(passwordEncoder().encode(enteredNewPassword));
            return true;
        } else {
            return false;
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepo.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
    }
}
