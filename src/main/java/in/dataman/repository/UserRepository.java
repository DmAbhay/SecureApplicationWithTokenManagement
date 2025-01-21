package in.dataman.repository;



import org.springframework.data.jpa.repository.JpaRepository;
import in.dataman.entity.UserEntity;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByUsername(String username);
    
    
    public boolean existsByUsername(String username);
}

