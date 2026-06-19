package com.ahmadre.hinata.me;

import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;

public interface RefreshSessionRepository extends MongoRepository<RefreshSession, String> {

	List<RefreshSession> findByUserIdOrderByLastActiveAtDesc(String userId);

	void deleteByUserId(String userId);

	void deleteByUserIdAndIdNot(String userId, String id);
}
