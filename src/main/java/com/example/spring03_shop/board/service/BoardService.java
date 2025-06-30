package com.example.spring03_shop.board.service;

import java.util.List;

import com.example.spring03_shop.board.dto.BoardDTO;
import com.example.spring03_shop.board.dto.PageDTO;

public interface BoardService {
	public long countProcess(); 
	public List<BoardDTO> listProcess(PageDTO pv);
	public void insertProcess(BoardDTO dto);
	public BoardDTO contentProcess(long num);
	public void updateProcess(BoardDTO dto, String tempDir);
	public void deleteProcess(long num, String tempDir);
}
