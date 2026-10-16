package com.nttdata.auth_service.config;

import com.nttdata.auth_service.model.User;
import com.nttdata.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Inicializa un usuario por defecto al arrancar {@code auth-service} si aún no existe.
 * <p>
 * Permite disponer de credenciales válidas desde el primer arranque para probar el flujo de
 * autenticación. Las credenciales se externalizan en {@code app.default-user.*}, por lo que
 * pueden cambiarse sin tocar código (Parte II: "no deben tener configuraciones en el código").
 *
 * @author NTT Data
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements ApplicationRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /** Usuario por defecto. */
    @Value("${app.default-user.username:admin}")
    private String defaultUsername;

    /** Contraseña por defecto. */
    @Value("${app.default-user.password:admin123}")
    private String defaultPassword;

    /** Rol por defecto. */
    @Value("${app.default-user.role:ADMIN}")
    private String defaultRole;

    @Override
    public void run(ApplicationArguments args) {
        userRepository.existsByUsername(defaultUsername)
                .flatMap(exists -> Boolean.TRUE.equals(exists)
                        ? Mono.empty()
                        : userRepository.save(User.builder()
                                .username(defaultUsername)
                                .password(passwordEncoder.encode(defaultPassword))
                                .role(defaultRole)
                                .build()))
                .doOnNext(created -> log.info("Default auth user '{}' created with role {}",
                        created.getUsername(), created.getRole()))
                .subscribe();
    }
}
