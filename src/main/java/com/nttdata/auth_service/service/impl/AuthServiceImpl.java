package com.nttdata.auth_service.service.impl;

import com.nttdata.auth_service.dto.LoginRequest;
import com.nttdata.auth_service.dto.RegisterRequest;
import com.nttdata.auth_service.dto.TokenResponse;
import com.nttdata.auth_service.dto.UserResponse;
import com.nttdata.auth_service.exception.InvalidCredentialsException;
import com.nttdata.auth_service.mapper.AuthMapper;
import com.nttdata.auth_service.model.User;
import com.nttdata.auth_service.repository.UserRepository;
import com.nttdata.auth_service.security.JwtService;
import com.nttdata.auth_service.service.AuthService;
import io.reactivex.rxjava3.core.Maybe;
import io.reactivex.rxjava3.core.Single;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Locale;

/**
 * Implementación del servicio de autenticación (Parte III) con el modelo de reactividad de
 * <b>RxJava 3</b> ({@link Single} / {@link Maybe}).
 * <p>
 * Reglas aplicadas:
 * <ul>
 *     <li>el login valida que el usuario exista y que la contraseña coincida con el hash
 *     almacenado; si no, lanza {@link InvalidCredentialsException} (HTTP 401);</li>
 *     <li>el registro impide duplicar nombres de usuario y guarda la contraseña cifrada
 *     (BCrypt).</li>
 * </ul>
 * Los repositorios reactivos (Reactor) se adaptan al borde con {@code fromPublisher}.
 *
 * @author NTT Data
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Override
    public Single<TokenResponse> login(LoginRequest request) {
        if (request == null || isBlank(request.getUsername()) || isBlank(request.getPassword())) {
            return Single.error(new IllegalArgumentException("Usuario y contraseña son obligatorios"));
        }

        return Maybe.fromPublisher(userRepository.findByUsername(request.getUsername()))
                .switchIfEmpty(Maybe.error(new InvalidCredentialsException("Credenciales inválidas")))
                .flatMap(user -> {
                    if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                        return Maybe.error(new InvalidCredentialsException("Credenciales inválidas"));
                    }
                    return Maybe.just(jwtService.generateToken(user));
                })
                .toSingle();
    }

    @Override
    public Single<UserResponse> register(RegisterRequest request) {
        if (request == null || isBlank(request.getUsername()) || isBlank(request.getPassword())) {
            return Single.error(new IllegalArgumentException("Usuario y contraseña son obligatorios"));
        }

        return Single.fromPublisher(userRepository.existsByUsername(request.getUsername()))
                .flatMap(exists -> {
                    if (Boolean.TRUE.equals(exists)) {
                        return Single.error(new IllegalArgumentException("El usuario ya existe"));
                    }
                    User user = User.builder()
                            .username(request.getUsername())
                            .password(passwordEncoder.encode(request.getPassword()))
                            .role(resolveRole(request.getRole()))
                            .build();
                    log.info("Registering auth user {}", request.getUsername());
                    return Single.fromPublisher(userRepository.save(user));
                })
                .map(AuthMapper::toResponse);
    }

    /**
     * Normaliza el rol recibido (por defecto {@code USER}).
     *
     * @param role rol recibido, puede ser nulo o vacío
     * @return rol en mayúsculas
     */
    private String resolveRole(String role) {
        if (isBlank(role)) {
            return "USER";
        }
        return role.toUpperCase(Locale.ROOT);
    }

    /**
     * Comprueba si una cadena es nula o está vacía.
     *
     * @param value cadena a comprobar
     * @return {@code true} si es nula o vacía
     */
    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
