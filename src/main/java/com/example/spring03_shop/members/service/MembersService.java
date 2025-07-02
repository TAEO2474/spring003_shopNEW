package com.example.spring03_shop.members.service;

import java.util.Optional;

import com.example.spring03_shop.members.dto.AuthInfo;
import com.example.spring03_shop.members.dto.ChangePwdCommand;
import com.example.spring03_shop.members.dto.MembersDTO;
import com.example.spring03_shop.members.entity.MembersEntity;

public interface MembersService {
	public AuthInfo addMemberProcess(MembersDTO dto);
	public AuthInfo loginProcess(MembersDTO dto);
	public MembersDTO  getByMemberProcess(String memberEmail);
	public AuthInfo updateMemberProcess(MembersDTO dto);
	public void updatePassProcess(String memberEmail, ChangePwdCommand changePwd);
	
	public void deleteMemberProcess(String memberEmail);
	public Optional<MembersEntity> findByEmail(String memberEmail); 
	}





	
	

