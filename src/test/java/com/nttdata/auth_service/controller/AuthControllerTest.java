package com.nttdata.auth_service.controller;

import com.nttdata.auth_service.config.TestSecurityConfig;
import com.nttdata.auth_service.dto.LoginRequest;
import com.nttdata.auth_service.dto.RegisterRequest;
import com.nttdata.auth_service.dto.TokenResponse;
import com.nttdata.auth_service.dto.UserResponse;
import com.nttdata.auth_service.exception.InvalidCredentialsException;
import com.nttdata.auth_service.service.AuthService;
import com.nttdata.commons.resilience.error.StandardApiExceptionHandler;
import io.reactivex.rxjava3.core.Single;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Pruebas del controlador de autenticación, que implementa la interfaz {@code AuthApi}
 * generada desde el contrato OpenAPI (<i>contract-first</i>).
 * <p>
 * El servicio se mockea devolviendo tipos de <b>RxJava 3</b> ({@code Single}); se verifica
 * que el controlador los adapta a Reactor y traduce los errores a los códigos HTTP
 * esperados (401 credenciales inválidas, 400 datos inválidos).
 *
 * @author NTT Data
 */
@WebFluxTest(controllers = AuthController.class)
@Import({TestSecurityConfig.class, StandardApiExceptionHandler.class})
class AuthControllerTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    private AuthService authService;

    @Test
    @DisplayName("POST /auth/login: Retorna 200 con el token cuando las credenciales son válidas")
    void login_shouldReturnToken() {
        TokenResponse token = new TokenResponse();
        token.setAccessToken("jwt-token");
        token.setTokenType("Bearer");
        token.setExpiresIn(3600L);

        when(authService.login(any(LoginRequest.class))).thenReturn(Single.just(token));

        webTestClient.post()
                .uri("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"admin\",\"password\":\"admin123\"}")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.accessToken").isEqualTo("jwt-token")
                .jsonPath("$.tokenType").isEqualTo("Bearer");
    }

    @Test
    @DisplayName("POST /auth/login: Retorna 401 si las credenciales son inválidas")
    void login_whenInvalidCredentials_shouldReturnUnauthorized() {
        when(authService.login(any(LoginRequest.class)))
                .thenReturn(Single.error(new InvalidCredentialsException("Credenciales inválidas")));

        webTestClient.post()
                .uri("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"admin\",\"password\":\"bad\"}")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("POST /auth/register: Retorna 201 con el usuario creado")
    void register_shouldReturnCreated() {
        UserResponse user = new UserResponse();
        user.setId("u2");
        user.setUsername("new");
        user.setRole("USER");

        when(authService.register(any(RegisterRequest.class))).thenReturn(Single.just(user));

        webTestClient.post()
                .uri("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"new\",\"password\":\"pw\"}")
                .exchange()
                .expectStatus().isCreated()
                .expectBody()
                .jsonPath("$.username").isEqualTo("new")
                .jsonPath("$.role").isEqualTo("USER");
    }

    @Test
    @DisplayName("POST /auth/register: Retorna 400 si el usuario ya existe")
    void register_whenDuplicate_shouldReturnBadRequest() {
        when(authService.register(any(RegisterRequest.class)))
                .thenReturn(Single.error(new IllegalArgumentException("El usuario ya existe")));

        webTestClient.post()
                .uri("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"admin\",\"password\":\"pw\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.message").isEqualTo("El usuario ya existe");
    }
}
