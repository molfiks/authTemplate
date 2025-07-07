package com.example.authtemplate.refreshtoken;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Integer> {
    Optional<RefreshToken> findByRefreshToken(String refreshToken);

    List<RefreshToken> findRefreshTokensByUserId(Integer userId);
}
