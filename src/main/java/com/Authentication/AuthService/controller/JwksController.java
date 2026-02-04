package com.Authentication.AuthService.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.Authentication.AuthService.dto.Jwks.JwksResponseDto;
import com.Authentication.AuthService.dto.Jwks.OpenIdConfigurationDto;
import com.Authentication.AuthService.services.oauth.JwksService;
import com.Authentication.AuthService.services.oauth.OpenIdConfigurationService;

@RestController
@RequestMapping(".well-known")
@RequiredArgsConstructor
@Slf4j
public class JwksController {
    private final JwksService jwksService;
    private final OpenIdConfigurationService openIdConfigurationService;

    @GetMapping("/jwks.json")
    public ResponseEntity<JwksResponseDto> jwks() {
        return ResponseEntity.ok(jwksService.getJwks());
    }

    @GetMapping("openid-configuration")
    public ResponseEntity<OpenIdConfigurationDto> openIdConfiguration() {
        return ResponseEntity.ok(openIdConfigurationService.getConfiguration());
    }
}