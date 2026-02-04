package com.Authentication.AuthService.services.auth.crypto;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.util.Base64;
import java.util.Optional;

import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class FileKeyStore {
    public Optional<byte[]> read(File file) {
        if (!file.exists())
            return Optional.empty();

        try {
            return Optional.of(
                    Base64.getDecoder().decode(
                            new String(Files.readAllBytes(file.toPath()))
                                    .replaceAll("-----.*?-----", "")
                                    .replaceAll("\\s", "")));
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read key file", e);
        }
    }

    public void write(File file, String header, byte[] keyBytes, String footer) {
        try {
            file.getParentFile().mkdirs();
            Files.writeString(file.toPath(),
                    header + "\n" + Base64.getEncoder().encodeToString(keyBytes) + "\n" + footer);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot write key file", e);
        }
    }
}
