package com.nttdata.auth_service.security;

import com.nttdata.auth_service.dto.TokenResponse;
import com.nttdata.auth_service.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

/**
 * Servicio encargado de firmar los tokens <b>JWT</b> que emite {@code auth-service}.
 * <p>
 * El token es firmado con HMAC-SHA256 usando una clave simétrica externalizada
 * ({@code app.jwt.secret}) que los microservicios de negocio comparten para validarlo como
 * <i>OAuth2 Resource Servers</i>. El emisor ({@code iss}) y la vigencia se externalizan en
 * {@code app.jwt.issuer} y {@code app.jwt.expiration-seconds}.
 *
 * @author NTT Data
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtEncoder jwtEncoder;

    /** Emisor del token. */
    @Value("${app.jwt.issuer:bank-system}")
    private String issuer;

    /** Vigencia del token en segundos. */
    @Value("${app.jwt.expiration-seconds:3600}")
    private long expirationSeconds;

    /**
     * Genera un token JWT firmado para el usuario autenticado.
     *
     * @param user usuario autenticado
     * @return DTO con el token, su tipo y su vigencia
     */
    public TokenResponse generateToken(User user) {
        Instant now = Instant.now();
        String role = user.getRole() != null ? user.getRole() : "USER";

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expirationSeconds))
                .subject(user.getUsername())
                .claim("roles", List.of(role))
                .build();

        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        String token = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        log.info("JWT generated for user {} with role {}", user.getUsername(), role);

        TokenResponse response = new TokenResponse();
        response.setAccessToken(token);
        response.setTokenType("Bearer");
        response.setExpiresIn(expirationSeconds);
        return response;
    }
}
