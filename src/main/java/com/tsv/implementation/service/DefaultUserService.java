package com.tsv.implementation.service;

import org.springframework.security.core.userdetails.UserDetailsService;

import com.tsv.implementation.dto.UserRegisteredDTO;
import com.tsv.implementation.model.User;


public interface DefaultUserService extends UserDetailsService{

	User save(UserRegisteredDTO userRegisteredDTO);

	String generateOtp(User user);



	
}
