package in.dataman.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import in.dataman.entity.Users;
import in.dataman.repository.UsersRepository;

@Service
public class UsersService {
	
	@Autowired
	private UsersRepository userRepository;
	
	public Users addUser(Users user) {
		return userRepository.save(user);
	}
	

}
