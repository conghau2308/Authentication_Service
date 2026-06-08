package com.Authentication.AuthService.services.auth.wifakey;

import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

/**
 * Server-side LDPC decode for the WiFaKey fuzzy commitment scheme.
 *
 * Runs the trained Neural-MS decoder (ONNX, 25 iterations) that used to ship
 * inside the client .exe. The client now only computes and sends the noisy
 * codeword c' = b_selected XOR helper_data; this service decodes it back to
 * the enrolled codeword, extracts the key bits and returns SHA-256(key) for
 * the caller to compare against the stored hash.
 *
 * Code parameters (BaseGraph2_Set0, Z=16) are fixed for every enrolled user —
 * changing them would require re-enrolling all users.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class LdpcDecoderService {

    private static final int N = 52;
    private static final int M = 42;
    private static final int Z = 16;
    private static final int FEATURE_LEN = N * Z;     // 832
    private static final int KEY_LEN = (N - M) * Z;   // 160

    private final ResourceLoader resourceLoader;

    @Value("${wifakey.ldpc.decoder-model-path}")
    private String decoderModelPath;

    private OrtEnvironment environment;
    private OrtSession session;
    private String inputName;
    private String outputName;

    @PostConstruct
    void initialize() throws IOException, OrtException {
        Resource modelResource = resourceLoader.getResource(decoderModelPath);
        String modelPath = modelResource.getFile().getAbsolutePath();

        environment = OrtEnvironment.getEnvironment();
        session = environment.createSession(modelPath, new OrtSession.SessionOptions());
        inputName = session.getInputNames().iterator().next();
        outputName = session.getOutputNames().iterator().next();

        log.info("WiFaKey LDPC decoder loaded from {}", modelPath);
    }

    /**
     * Decodes the noisy codeword c' and returns SHA-256(reconstructed_key).
     *
     * @param cPrime noisy codeword — FEATURE_LEN bytes, each value 0 or 1
     */
    public byte[] reconstructKeyHash(byte[] cPrime) {
        if (cPrime == null || cPrime.length != FEATURE_LEN) {
            throw new IllegalArgumentException(
                    "c' must be " + FEATURE_LEN + " bytes, got "
                            + (cPrime == null ? "null" : cPrime.length));
        }

        try {
            // BPSK modulation: 0 -> -1, 1 -> +1, reshaped to [1, N, Z]
            float[][][] llr = new float[1][N][Z];
            for (int i = 0; i < FEATURE_LEN; i++) {
                llr[0][i / Z][i % Z] = cPrime[i] * 2.0f - 1.0f;
            }

            try (OnnxTensor inputTensor = OnnxTensor.createTensor(environment, llr);
                 OrtSession.Result result = session.run(Map.of(inputName, inputTensor))) {

                float[][] decodedLlr = (float[][]) result.get(outputName)
                        .orElseThrow(() -> new IllegalStateException("LDPC decoder produced no output"))
                        .getValue();

                byte[] key = new byte[KEY_LEN];
                for (int i = 0; i < KEY_LEN; i++) {
                    key[i] = decodedLlr[0][i] > 0 ? (byte) 1 : (byte) 0;
                }

                return MessageDigest.getInstance("SHA-256").digest(key);
            }
        } catch (OrtException e) {
            throw new IllegalStateException("LDPC decode failed", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
