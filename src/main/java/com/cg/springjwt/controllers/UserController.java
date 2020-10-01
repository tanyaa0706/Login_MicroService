package com.cg.springjwt.controllers;

import java.util.HashMap;
import java.util.Map;

import javax.validation.Valid;

import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.cg.springjwt.models.User;
import com.cg.springjwt.models.UserModel;
import com.cg.springjwt.payload.request.ChangePasswordRequest;
import com.cg.springjwt.payload.response.MessageResponse;
import com.cg.springjwt.repository.UserRepository;
import com.cg.springjwt.security.services.UserDetailsServiceImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/user")
public class UserController {

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	private UserDetailsServiceImpl userDetailsServiceImpl;

	@GetMapping
	@PreAuthorize("hasAuthority('CUSTOMER')or hasAuthority('ADMIN')")
	public UserModel getUserDetails(Authentication authentication) {
		return userDetailsServiceImpl.getUserByUserName(authentication.getName());
	}

	@PutMapping
	@PreAuthorize("hasAuthority('CUSTOMER') or hasAuthority('ADMIN')")
	public ResponseEntity<?> updateUser(Authentication authentication, @Valid @RequestBody UserModel userModel) {

		User user = userRepository.findByUsername(authentication.getName()).orElse(null);

		if (user == null) {
			return ResponseEntity.badRequest().body(new MessageResponse("Error: User does not exist!"));
		}

		BeanUtils.copyProperties(userModel, user);
		userRepository.save(user);

		Map<String, Object> responseMap = new HashMap<>();
		responseMap.put("success", true);

		return ResponseEntity.ok(responseMap);
	}

	@PostMapping("/change-password")
	@PreAuthorize("hasAuthority('CUSTOMER') or hasAuthority('ADMIN')")
	public ResponseEntity<?> changePassword(Authentication authentication,
			@Valid @RequestBody ChangePasswordRequest changePasswordRequest) {

		User user = userRepository.findByUsername(authentication.getName()).orElse(null);

		if (user == null) {
			return ResponseEntity.badRequest().body(new MessageResponse("Error: User does not exist!"));
		}
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authentication.getName(),
				changePasswordRequest.getOldPassword()));

		user.setPassword(encoder.encode(changePasswordRequest.getNewPassword()));
		userRepository.save(user);

		Map<String, Object> responseMap = new HashMap<>();
		responseMap.put("success", true);

		return ResponseEntity.ok(responseMap);
	}

}
