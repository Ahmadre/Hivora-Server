package com.ahmadre.hinata.space;

import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;

public interface SpaceRepository extends MongoRepository<Space, String> {

	List<Space> findAllByOrderBySortOrderAscNameAsc();

	boolean existsByName(String name);
}
