package com.Authentication.AuthService.dto;

import java.util.List;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PaginatedResponse<T> {
    private List<T> items;
    private int page;
    private int size;
    private long totalItems;
    private int totalPages;
}
