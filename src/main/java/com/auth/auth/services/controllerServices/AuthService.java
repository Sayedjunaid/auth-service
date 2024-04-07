package com.auth.auth.services.controllerServices;

import com.auth.auth.entity.User;
import com.auth.auth.model.UserDetails;
import com.auth.auth.model.UserLogin;
import com.auth.auth.services.JwtService;
import com.auth.auth.services.repositoriesServices.UserRepositoryService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;

import java.util.HashMap;
import java.util.Map;

@Service
public class AuthService {

    public static String validationErrorMessage;

    private static final int PASSWORD_ENCODER_STRENGTH = 10;

    @Autowired
    UserRepositoryService userRepositoryService;

    @Autowired
    JwtService jwtService;

    public boolean validate (BindingResult validationResults) {
        if(validationResults.hasErrors()) {
            StringBuilder errorMessage = new StringBuilder("Validation failed: ");
            for (FieldError fieldError : validationResults.getFieldErrors()) {
                errorMessage.append(fieldError.getDefaultMessage()).append("; ");
            }
            validationErrorMessage = String.valueOf(errorMessage);
            return true;
        }
        return false;
    }

    private String encodePassword (String password) {
        return new BCryptPasswordEncoder(PASSWORD_ENCODER_STRENGTH).encode(password);
    }


    public void registerUser (UserDetails userDetails) {
        User user = new User();
        user.setName(userDetails.getName());
        user.setEmail(userDetails.getEmail());
        user.setPassword(encodePassword(userDetails.getPassword()));
        user.setRole(User.ROLE.USER);
        userRepositoryService.insertUser(user);
    }


    public boolean checkUserExistence (String email) {
        return userRepositoryService.getUserByEmail(email) != null;
    }

    public User getUserByEmail (String email) {
        return  userRepositoryService.getUserByEmail(email);
    }

    public boolean isAuthenticUser (User user, UserLogin userCredentials) {
        if(user == null)
            user = getUserByEmail(userCredentials.getEmail());
        return new BCryptPasswordEncoder(AuthService.PASSWORD_ENCODER_STRENGTH).matches(userCredentials.getPassword(), user.getPassword());
    }


    public String getAuthenticatedToken (User user) {
        try{
            Map<String, Object> claims = new HashMap<>();
            claims.put("email", user.getEmail());
            claims.put("role", user.getRole());
            claims.put("uid", user.getId());
            return jwtService.generateToken("1d",claims);
        } catch (Exception e) {
            throw  new RuntimeException(e);
        }
    }


    public Map<String, Object> getClaims (HttpServletRequest request) {
        return jwtService.extractClaims(jwtService.extractToken(request));
    }


}
