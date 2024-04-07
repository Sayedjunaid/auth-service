package com.auth.auth.services.repositoriesServices;

import com.auth.auth.entity.User;
import com.auth.auth.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserRepositoryService {


    @Autowired
    UserRepository userRepository;


    public void insertUser (User user) {
         userRepository.insert(user);
    }


    public User getUserByEmail (String email) {
        return userRepository.findByEmail(email);
    }


}
