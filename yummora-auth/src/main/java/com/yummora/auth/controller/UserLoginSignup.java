package com.yummora.auth.controller;

import com.yummora.auth.dto.UserLoginRequest;
import com.yummora.auth.dto.UserLoginResponse;
import com.yummora.auth.dto.UserRegisterRequest;
import com.yummora.auth.dto.UserRegisterResponse;
import com.yummora.auth.entity.UserEntity;
import com.yummora.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class UserLoginSignup {
    @Autowired
    UserService userService;

    @PostMapping("/login")
    public ResponseEntity<UserLoginResponse> login(@RequestBody UserLoginRequest request, HttpServletRequest servletRequest){
        UserLoginResponse response = userService.login(request);
        if(response == null){
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(response,HttpStatus.OK);
    }

    @PostMapping("/register-user")
    public ResponseEntity<UserRegisterResponse> registerUser(@RequestBody UserRegisterRequest req, HttpServletRequest request){
        UserEntity user= UserEntity.builder()
                            .userName(req.getUserName())
                            .emailId(req.getEmailId())
                            .phoneNumber(req.getPhoneNumber())
                            .password(req.getPassword())
                            .membership("None")
                            .build();

        UserRegisterResponse response = userService.saveUser(user);
        return ResponseEntity.ok(response);
    }
}
