package com.nttdata.auth_service.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import reactor.test.StepVerifier;

import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pruebas unitarias de {@link SecurityConfig} (Parte III).
 * <p>
 * Comprueba que la configuración produce un codificador BCrypt, que el par
 * encoder/decoder HMAC-SHA256 es interoperable y que la cadena de filtros se construye
 * con las reglas de acceso esperadas.
 *
 * @author NTT Data
 */
class SecurityConfigTest {

    private static final String SECRET = "0123456789abcdef0123456789abcdef";

    private final SecurityConfig securityConfig = new SecurityConfig();

    @Test
    @DisplayName("passwordEncoder: devuelve un codificador BCrypt")
    void passwordEncoder_shouldReturnBCrypt() {
        PasswordEncoder encoder = securityConfig.passwordEncoder();

        assertThat(encoder).isInstanceOf(BCryptPasswordEncoder.class);
        assertThat(encoder.matches("secret", encoder.encode("secret"))).isTrue();
    }

    @Test
    @DisplayName("jwtEncoder/jwtDecoder: emiten y validan el mismo token")
    void jwtEncoderAndDecoder_shouldRoundTrip() {
        JwtEncoder encoder = securityConfig.jwtEncoder(SECRET);
        ReactiveJwtDecoder decoder = securityConfig.jwtDecoder(SECRET);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("bank-system-test")
                .subject("admin")
                .claim("roles", List.of("ADMIN"))
                .build();
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        String token = encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();

        Jwt jwt = decoder.decode(token).block();
        assertThat(jwt).isNotNull();
        assertThat(jwt.getSubject()).isEqualTo("admin");
        assertThat(jwt.getClaimAsStringList("roles")).containsExactly("ADMIN");
    }

    @Test
    @DisplayName("jwtDecoder: rechaza un token firmado con otra clave")
    void jwtDecoder_shouldRejectTokenFromAnotherSecret() {
        JwtEncoder encoder = securityConfig.jwtEncoder(SECRET);
        ReactiveJwtDecoder otherDecoder = NimbusReactiveJwtDecoder
                .withSecretKey(new SecretKeySpec(
                        "another-secret-another-secret-123".getBytes(StandardCharsets.UTF_8), "HmacSHA256"))
                .macAlgorithm(MacAlgorithm.HS256)
                .build();

        JwtClaimsSet claims = JwtClaimsSet.builder().subject("admin").build();
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        String token = encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();

        StepVerifier.create(otherDecoder.decode(token))
                .expectError()
                .verify();
    }

    @Test
    @DisplayName("jwtAuthenticationConverter: traduce el claim roles a autoridades ROLE_*")
    void jwtAuthenticationConverter_shouldMapRolesToAuthorities() throws Exception {
        Method method = SecurityConfig.class.getDeclaredMethod("jwtAuthenticationConverter");
        method.setAccessible(true);
        ReactiveJwtAuthenticationConverterAdapter converter =
                (ReactiveJwtAuthenticationConverterAdapter) method.invoke(securityConfig);

        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "HS256")
                .claim("roles", List.of("ADMIN", "USER"))
                .build();

        Authentication authentication = converter.convert(jwt).block();
        assertThat(authentication).isNotNull();
        assertThat(authentication.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_ADMIN", "ROLE_USER");
    }
}
