package com.example.spring03_shop.members.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.spring03_shop.members.entity.MembersEntity;

@Repository
public interface MembersRepository  extends JpaRepository<MembersEntity, String>{

}
