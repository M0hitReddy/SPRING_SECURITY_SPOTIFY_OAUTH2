package com.muzer.App.Repository;


import com.muzer.App.Models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
//    User findById(long id);
    User findByEmail(String email);

}
