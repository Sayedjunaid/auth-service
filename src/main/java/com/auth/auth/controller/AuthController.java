package com.auth.auth.controller;

import com.auth.auth.entity.User;
import com.auth.auth.model.GenericResponse;
import com.auth.auth.model.UserDetails;
import com.auth.auth.model.UserLogin;
import com.auth.auth.services.controllerServices.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;


@SuppressWarnings("MVCPathVariableInspection")
@RestController
@RequestMapping(path = AuthController.REQUEST_PATH, produces = MediaType.APPLICATION_JSON_VALUE)
public class AuthController {

    public static  final String REQUEST_PATH = "/api/v1/auth";

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);


    @Autowired
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }


    @PostMapping("/register")
    public ResponseEntity<?> register (@Valid @RequestBody UserDetails userDetails, BindingResult bindingResult) {
        try{
            if(authService.validate(bindingResult))
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new GenericResponse<>(false, AuthService.validationErrorMessage, null));
            if(authService.checkUserExistence(userDetails.getEmail()))
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new GenericResponse<>(false, "email already exist please login", null));
            authService.registerUser(userDetails);
            return ResponseEntity.status(HttpStatus.OK).body(new GenericResponse<>(true, "registered", null));
        } catch (Exception e) {
            LOGGER.error("Exception at register -> " + e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new GenericResponse<>(false, "issue with the server try again later", null));
        }
    }



    @PostMapping("/login")
    public ResponseEntity<?> login (@Valid @RequestBody UserLogin userCredentials, BindingResult bindingResult) {
        try{
            if(authService.validate(bindingResult))
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new GenericResponse<>(false, AuthService.validationErrorMessage, null));
            User user = authService.getUserByEmail(userCredentials.getEmail().trim());
            if(user == null)
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new GenericResponse<>(false, "email doesn't exist please register", null));
            if(!authService.isAuthenticUser(user, userCredentials))
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new GenericResponse<>(false, "Invalid credentials", null));
            String token = authService.getAuthenticatedToken(user);
            return ResponseEntity.status(HttpStatus.OK).header("authorization", "Bearer " + token).body(new GenericResponse<>(true, "welcome "+ user.getName(), null));
        } catch (Exception e) {
            LOGGER.error("Exception at login -> "+ e);
            return  ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new GenericResponse<>(false, "issue with the server try again later", null));
        }
    }



    @GetMapping("/verifytoken")
    public ResponseEntity<?> verifyToken (HttpServletRequest request, Authentication authentication) {
        try{
            if(authentication.isAuthenticated())
                return ResponseEntity.status(HttpStatus.OK).body(new GenericResponse<>(true, "authenticated", authService.getClaims(request)));
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new GenericResponse<>(false, "unauthenticated", null));
        } catch (Exception e) {
            LOGGER.error("Exception at verify token -> "+ e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new GenericResponse<>(false, "issue with the server please try again later", null));
        }
    }





}
