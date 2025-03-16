package com.example.basicsecurityv2.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class SignUpResponseDTO {
    private boolean success;
    private String message;
}