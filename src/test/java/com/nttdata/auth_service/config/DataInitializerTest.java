package com.nttdata.auth_service.config;

import com.nttdata.auth_service.model.User;
import com.nttdata.auth_service.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Pruebas unitarias de {@link DataInitializer} (Parte III).
 * <p>
 * Verifica que el usuario por defecto se crea con la contraseña cifrada y el rol
 * externalizado, y que no se duplica si ya existe.
 *
 * @author NTT Data
 */
@ExtendWith(MockitoExtension.class)
class DataInitializerTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    private DataInitializer dataInitializer;

    @BeforeEach
    void setUp() {
        dataInitializer = new DataInitializer(userRepository, passwordEncoder);
        ReflectionTestUtils.setField(dataInitializer, "defaultUsername", "admin");
        ReflectionTestUtils.setField(dataInitializer, "defaultPassword", "admin123");
        ReflectionTestUtils.setField(dataInitializer, "defaultRole", "ADMIN");
    }

    @Test
    @DisplayName("run: crea el usuario por defecto con la contraseña cifrada")
    void run_whenUserDoesNotExist_shouldCreateDefaultUser() {
        when(userRepository.existsByUsername("admin")).thenReturn(Mono.just(false));
        when(passwordEncoder.encode("admin123")).thenReturn("encoded-password");
        when(userRepository.save(any(User.class)))
                .thenAnswer(invocation -> Mono.just(invocation.getArgument(0)));

        dataInitializer.run(null);

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        User created = captor.getValue();
        assertThat(created.getUsername()).isEqualTo("admin");
        assertThat(created.getPassword()).isEqualTo("encoded-password");
        assertThat(created.getRole()).isEqualTo("ADMIN");
    }

    @Test
    @DisplayName("run: no crea el usuario si ya existe")
    void run_whenUserExists_shouldNotCreateUser() {
        when(userRepository.existsByUsername("admin")).thenReturn(Mono.just(true));

        dataInitializer.run(null);

        verify(userRepository, never()).save(any(User.class));
    }
}
