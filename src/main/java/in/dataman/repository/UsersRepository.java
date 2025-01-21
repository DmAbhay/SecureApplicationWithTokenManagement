package in.dataman.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import in.dataman.entity.Users;

public interface UsersRepository  extends JpaRepository<Users, Long>{

	
}
