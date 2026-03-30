package com.Authentication.AuthService.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.Authentication.AuthService.dto.jwks.JwksResponseDto;
import com.Authentication.AuthService.dto.jwks.OpenIdConfigurationDto;
import com.Authentication.AuthService.services.oauth.JwksService;
import com.Authentication.AuthService.services.oauth.OpenIdConfigurationService;

import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@RequestMapping("/.well-known")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "OAuth2 Well-Known Endpoints", description = "Public OAuth2/OpenID Connect well-known configuration and discovery endpoints")
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