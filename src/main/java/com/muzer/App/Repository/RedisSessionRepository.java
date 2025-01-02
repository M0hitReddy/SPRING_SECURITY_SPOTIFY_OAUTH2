package com.muzer.App.Repository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Repository
public class RedisSessionRepository {

    private final RedisTemplate<String, Object> redisTemplate;

    @Autowired
    public RedisSessionRepository(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void saveSession(String sessionId, Object sessionData) {
        redisTemplate.opsForValue().set(sessionId, sessionData, 10, TimeUnit.SECONDS);
    }

    public Object getSession(String sessionId) {
        return redisTemplate.opsForValue().get(sessionId);
    }


    public Map<String, Object> getAllSessions() {
        Set<String> keys = redisTemplate.keys("*");
        return keys.stream()
                .filter(key -> redisTemplate.opsForValue().get(key) != null)
                .collect(Collectors.toMap(
                        key -> key,
                        key -> redisTemplate.opsForValue().get(key)
                ))
                .entrySet().stream()

                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    public void deleteSession(String sessionId) {
        redisTemplate.delete(sessionId);
    }
}