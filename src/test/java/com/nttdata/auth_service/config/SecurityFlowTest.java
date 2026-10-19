package com.nttdata.auth_service.config;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nttdata.auth_service.controller.AuthController;
import com.nttdata.auth_service.dto.LoginRequest;
import com.nttdata.auth_service.dto.TokenResponse;
import com.nttdata.auth_service.service.AuthService;
import io.reactivex.rxjava3.core.Single;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Prueba del <b>flujo de seguridad</b> (Parte III) con la configuración real de
 * {@link SecurityConfig}, no con la permisiva de pruebas.
 * <p>
 * Comprueba que {@code /auth/login} es público, que cualquier otra ruta exige un JWT válido
 * y que un token firmado con otra clave simétrica es rechazado.
 *
 * @author NTT Data
 */
@WebFluxTest(controllers = AuthController.class)
@Import(SecurityConfig.class)
@TestPropertySource(properties = "app.jwt.secret=bank-system-super-secret-key-for-jwt-hs256-2026-nttdata")
class SecurityFlowTest {

    /** Clave compartida con los microservicios de negocio (misma que {@code app.jwt.secret}). */
    private static final String SECRET = "bank-system-super-secret-key-for-jwt-hs256-2026-nttdata";

    private static final String PROTECTED_PATH = "/auth/protected-resource";

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    private AuthService authService;

    @Test
    @DisplayName("POST /auth/login es público y devuelve el token")
    void loginShouldBePublic() {
        TokenResponse token = new TokenResponse();
        token.setAccessToken("access-token");
        token.setTokenType("Bearer");
        token.setExpiresIn(3600L);
        when(authService.login(any(LoginRequest.class))).thenReturn(Single.just(token));

        webTestClient.post().uri("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"admin\",\"password\":\"admin123\"}")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.accessToken").isEqualTo("access-token");
    }

    @Test
    @DisplayName("Una ruta protegida sin token responde 401")
    void protectedPathWithoutTokenIsUnauthorized() {
        webTestClient.get().uri(PROTECTED_PATH)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("Una ruta protegida con un JWT válido supera la seguridad")
    void protectedPathWithValidTokenPassesSecurity() {
        webTestClient.get().uri(PROTECTED_PATH)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + signedToken(SECRET))
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    @DisplayName("Un JWT firmado con otra clave es rechazado con 401")
    void tokenSignedWithAnotherKeyIsUnauthorized() {
        webTestClient.get().uri(PROTECTED_PATH)
                .header(HttpHeaders.AUTHORIZATION,
                        "Bearer " + signedToken("otra-clave-simetrica-distinta-para-hs256-000000"))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    /**
     * Firma un JWT HS256 con la clave indicada, igual que hace {@code auth-service}.
     *
     * @param secret clave simétrica de firma
     * @return token JWT firmado
     */
    private String signedToken(String secret) {
        SecretKey key = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        JwtEncoder encoder = new NimbusJwtEncoder(new ImmutableSecret<>(key));
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("bank-system")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(3600))
                .subject("admin")
                .claim("roles", List.of("ADMIN"))
                .build();
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
