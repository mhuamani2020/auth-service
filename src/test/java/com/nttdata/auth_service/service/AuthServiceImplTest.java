package com.nttdata.auth_service.service;

import com.nttdata.auth_service.dto.LoginRequest;
import com.nttdata.auth_service.dto.RegisterRequest;
import com.nttdata.auth_service.dto.TokenResponse;
import com.nttdata.auth_service.exception.InvalidCredentialsException;
import com.nttdata.auth_service.model.User;
import com.nttdata.auth_service.repository.UserRepository;
import com.nttdata.auth_service.security.JwtService;
import com.nttdata.auth_service.service.impl.AuthServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Pruebas unitarias de {@link AuthServiceImpl} (Parte III) con mocks.
 * <p>
 * La capa de servicio devuelve tipos de <b>RxJava 3</b>; como {@code Single} no implementa
 * {@code Publisher}, se adapta con {@code toFlowable()} para verificar con
 * {@code StepVerifier}.
 *
 * @author NTT Data
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthServiceImpl authService;

    private User user;
    private TokenResponse tokenResponse;

    @BeforeEach
    void setUp() {
        user = User.builder().id("u1").username("admin").password("hash").role("ADMIN").build();
        tokenResponse = new TokenResponse();
        tokenResponse.setAccessToken("jwt-token");
        tokenResponse.setTokenType("Bearer");
        tokenResponse.setExpiresIn(3600L);
    }

    @Test
    @DisplayName("login: Emite token cuando las credenciales son correctas")
    void login_whenValidCredentials_shouldReturnToken() {
        when(userRepository.findByUsername("admin")).thenReturn(Mono.just(user));
        when(passwordEncoder.matches("secret", "hash")).thenReturn(true);
        when(jwtService.generateToken(user)).thenReturn(tokenResponse);

        StepVerifier.create(authService.login(loginRequest("admin", "secret")).toFlowable())
                .assertNext(token -> assertThat(token.getAccessToken()).isEqualTo("jwt-token"))
                .verifyComplete();
    }

    @Test
    @DisplayName("login: Falla con credenciales inválidas si la contraseña no coincide")
    void login_whenWrongPassword_shouldFail() {
        when(userRepository.findByUsername("admin")).thenReturn(Mono.just(user));
        when(passwordEncoder.matches("wrong", "hash")).thenReturn(false);

        StepVerifier.create(authService.login(loginRequest("admin", "wrong")).toFlowable())
                .expectError(InvalidCredentialsException.class)
                .verify();
    }

    @Test
    @DisplayName("login: Falla con credenciales inválidas si el usuario no existe")
    void login_whenUserNotFound_shouldFail() {
        when(userRepository.findByUsername("ghost")).thenReturn(Mono.empty());

        StepVerifier.create(authService.login(loginRequest("ghost", "secret")).toFlowable())
                .expectError(InvalidCredentialsException.class)
                .verify();
    }

    @Test
    @DisplayName("login: Falla si el usuario está vacío")
    void login_whenBlankUsername_shouldFail() {
        StepVerifier.create(authService.login(loginRequest("  ", "secret")).toFlowable())
                .expectErrorMatches(ex -> ex instanceof IllegalArgumentException
                        && ex.getMessage().contains("obligatorios"))
                .verify();
    }

    @Test
    @DisplayName("register: Crea el usuario con rol por defecto USER")
    void register_whenNewUser_shouldCreateWithDefaultRole() {
        when(userRepository.existsByUsername("new")).thenReturn(Mono.just(false));
        when(passwordEncoder.encode("pw")).thenReturn("hash");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User toSave = invocation.getArgument(0);
            toSave.setId("u2");
            return Mono.just(toSave);
        });

        StepVerifier.create(authService.register(registerRequest("new", "pw", null)).toFlowable())
                .assertNext(response -> {
                    assertThat(response.getId()).isEqualTo("u2");
                    assertThat(response.getUsername()).isEqualTo("new");
                    assertThat(response.getRole()).isEqualTo("USER");
                })
                .verifyComplete();
    }

    @Test
    @DisplayName("register: Normaliza el rol recibido a mayúsculas")
    void register_whenRoleProvided_shouldUpperCaseRole() {
        when(userRepository.existsByUsername("new")).thenReturn(Mono.just(false));
        when(passwordEncoder.encode("pw")).thenReturn("hash");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User toSave = invocation.getArgument(0);
            toSave.setId("u3");
            return Mono.just(toSave);
        });

        StepVerifier.create(authService.register(registerRequest("new", "pw", "admin")).toFlowable())
                .assertNext(response -> assertThat(response.getRole()).isEqualTo("ADMIN"))
                .verifyComplete();
    }

    @Test
    @DisplayName("register: Falla si el usuario ya existe")
    void register_whenUserExists_shouldFail() {
        when(userRepository.existsByUsername("admin")).thenReturn(Mono.just(true));

        StepVerifier.create(authService.register(registerRequest("admin", "pw", "USER")).toFlowable())
                .expectErrorMatches(ex -> ex instanceof IllegalArgumentException
                        && ex.getMessage().contains("ya existe"))
                .verify();
    }

    @Test
    @DisplayName("register: Falla si la contraseña está vacía")
    void register_whenBlankPassword_shouldFail() {
        StepVerifier.create(authService.register(registerRequest("new", "  ", "USER")).toFlowable())
                .expectErrorMatches(ex -> ex instanceof IllegalArgumentException
                        && ex.getMessage().contains("obligatorios"))
                .verify();
    }

    private LoginRequest loginRequest(String username, String password) {
        LoginRequest request = new LoginRequest();
        request.setUsername(username);
        request.setPassword(password);
        return request;
    }

    private RegisterRequest registerRequest(String username, String password, String role) {
        RegisterRequest request = new RegisterRequest();
        request.setUsername(username);
        request.setPassword(password);
        request.setRole(role);
        return request;
    }
}
