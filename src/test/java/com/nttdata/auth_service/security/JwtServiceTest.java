package com.nttdata.auth_service.security;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nttdata.auth_service.dto.TokenResponse;
import com.nttdata.auth_service.model.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.util.ReflectionTestUtils;
import reactor.test.StepVerifier;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pruebas unitarias de {@link JwtService} (Parte III).
 * <p>
 * Se usa un {@link JwtEncoder} real firmado con HMAC-SHA256 (sin mocks) para comprobar que
 * el token emitido contiene el emisor, el sujeto, los roles y la vigencia configurada, y que
 * puede validarse con la misma clave simétrica que comparten los microservicios de negocio.
 *
 * @author NTT Data
 */
class JwtServiceTest {

    private static final String SECRET = "0123456789abcdef0123456789abcdef";
    private static final String ISSUER = "bank-system-test";
    private static final long EXPIRATION_SECONDS = 3600L;

    private JwtService jwtService;
    private ReactiveJwtDecoder decoder;

    @BeforeEach
    void setUp() {
        SecretKey key = toSecretKey(SECRET);
        JwtEncoder encoder = new NimbusJwtEncoder(new ImmutableSecret<>(key));
        decoder = NimbusReactiveJwtDecoder.withSecretKey(key)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();

        jwtService = new JwtService(encoder);
        ReflectionTestUtils.setField(jwtService, "issuer", ISSUER);
        ReflectionTestUtils.setField(jwtService, "expirationSeconds", EXPIRATION_SECONDS);
    }

    @Test
    @DisplayName("generateToken: emite un JWT firmado con emisor, sujeto, rol y vigencia")
    void generateToken_shouldIncludeClaimsAndExpiration() {
        User user = User.builder().username("admin").password("hash").role("ADMIN").build();

        TokenResponse response = jwtService.generateToken(user);

        assertThat(response.getAccessToken()).isNotBlank();
        assertThat(response.getTokenType()).isEqualTo("Bearer");
        assertThat(response.getExpiresIn()).isEqualTo(EXPIRATION_SECONDS);

        Jwt jwt = decoder.decode(response.getAccessToken()).block();
        assertThat(jwt).isNotNull();
        assertThat(jwt.getClaimAsString("iss")).isEqualTo(ISSUER);
        assertThat(jwt.getSubject()).isEqualTo("admin");
        assertThat(jwt.getClaimAsStringList("roles")).containsExactly("ADMIN");
        assertThat(jwt.getExpiresAt()).isNotNull();
        assertThat(jwt.getExpiresAt()).isAfter(Instant.now().plusSeconds(EXPIRATION_SECONDS - 60));
        assertThat(jwt.getExpiresAt()).isBefore(Instant.now().plusSeconds(EXPIRATION_SECONDS + 60));
    }

    @Test
    @DisplayName("generateToken: usa el rol USER cuando el usuario no tiene rol")
    void generateToken_whenRoleIsNull_shouldUseUserRole() {
        User user = User.builder().username("client").password("hash").role(null).build();

        TokenResponse response = jwtService.generateToken(user);

        Jwt jwt = decoder.decode(response.getAccessToken()).block();
        assertThat(jwt).isNotNull();
        assertThat(jwt.getClaimAsStringList("roles")).containsExactly("USER");
    }

    @Test
    @DisplayName("generateToken: respeta la vigencia externalizada")
    void generateToken_shouldUseConfiguredExpiration() {
        ReflectionTestUtils.setField(jwtService, "expirationSeconds", 60L);
        User user = User.builder().username("admin").role("ADMIN").build();

        TokenResponse response = jwtService.generateToken(user);

        assertThat(response.getExpiresIn()).isEqualTo(60L);
        Jwt jwt = decoder.decode(response.getAccessToken()).block();
        assertThat(jwt).isNotNull();
        Instant issuedAt = jwt.getIssuedAt();
        assertThat(ChronoUnit.SECONDS.between(issuedAt, jwt.getExpiresAt())).isEqualTo(60L);
    }

    @Test
    @DisplayName("generateToken: el token no es válido con otra clave simétrica")
    void generateToken_shouldNotValidateWithAnotherSecret() {
        User user = User.builder().username("admin").role("ADMIN").build();
        TokenResponse response = jwtService.generateToken(user);

        ReactiveJwtDecoder otherDecoder = NimbusReactiveJwtDecoder
                .withSecretKey(toSecretKey("another-secret-another-secret-123"))
                .macAlgorithm(MacAlgorithm.HS256)
                .build();

        StepVerifier.create(otherDecoder.decode(response.getAccessToken()))
                .expectError()
                .verify();
    }

    /**
     * Construye la clave simétrica HMAC-SHA256 a partir del secreto.
     *
     * @param secret secreto compartido
     * @return clave simétrica
     */
    private static SecretKey toSecretKey(String secret) {
        return new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }
}
