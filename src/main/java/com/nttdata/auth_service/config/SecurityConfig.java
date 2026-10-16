package com.nttdata.auth_service.config;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * Configuración de seguridad reactiva de {@code auth-service}.
 * <p>
 * <ul>
 *     <li><b>Autenticación</b>: publica {@code /auth/login} y {@code /auth/register} (y las
 *     rutas de actuator / documentación) para que un cliente sin token pueda autenticarse;
 *     protege el resto de endpoints exigiendo un JWT válido (el servicio es además
 *     <i>resource server</i> de sus propias APIs).</li>
 *     <li><b>Autorización</b>: los roles del claim {@code roles} del token se resuelven como
 *     autoridades {@code ROLE_*}.</li>
 *     <li><b>Emisión</b>: expone el {@link JwtEncoder} (firma HMAC-SHA256) y el
 *     {@link PasswordEncoder} (BCrypt) usados por el flujo de autenticación.</li>
 * </ul>
 * La clave simétrica se externaliza en {@code app.jwt.secret} (Config Server) y es la misma
 * que usan los microservicios de negocio para validar los tokens.
 *
 * @author NTT Data
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    /**
     * Define la cadena de filtros de seguridad reactiva.
     *
     * @param http configuración de seguridad reactiva
     * @return cadena de filtros de seguridad
     */
    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/auth/login", "/auth/register").permitAll()
                        .pathMatchers("/actuator/**", "/v3/api-docs/**",
                                "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        .anyExchange().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwtSpec -> jwtSpec
                        .jwtAuthenticationConverter(jwtAuthenticationConverter())))
                .build();
    }

    /**
     * Codificador de contraseñas basado en BCrypt.
     *
     * @return codificador de contraseñas
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Codificador de JWT firmados con HMAC-SHA256.
     *
     * @param secret clave simétrica externalizada
     * @return codificador de JWT
     */
    @Bean
    public JwtEncoder jwtEncoder(@Value("${app.jwt.secret}") String secret) {
        SecretKey key = toSecretKey(secret);
        return new NimbusJwtEncoder(new ImmutableSecret<>(key));
    }

    /**
     * Decodificador reactivo de JWT (para validar los tokens que el propio servicio recibe).
     *
     * @param secret clave simétrica externalizada
     * @return decodificador reactivo de JWT
     */
    @Bean
    public ReactiveJwtDecoder jwtDecoder(@Value("${app.jwt.secret}") String secret) {
        return NimbusReactiveJwtDecoder.withSecretKey(toSecretKey(secret))
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
    }

    /**
     * Resuelve las autoridades del usuario a partir del claim {@code roles} del JWT,
     * exponiéndolas como {@code ROLE_*} para la autorización.
     *
     * @return adaptador reactivo que traduce el JWT a una autenticación con roles
     */
    private ReactiveJwtAuthenticationConverterAdapter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName("roles");
        authoritiesConverter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return new ReactiveJwtAuthenticationConverterAdapter(jwtConverter);
    }

    private SecretKey toSecretKey(String secret) {
        return new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }
}
