package com.nttdata.auth_service.controller;

import com.nttdata.auth_service.api.AuthApi;
import com.nttdata.auth_service.dto.LoginRequest;
import com.nttdata.auth_service.dto.RegisterRequest;
import com.nttdata.auth_service.dto.TokenResponse;
import com.nttdata.auth_service.dto.UserResponse;
import com.nttdata.auth_service.exception.InvalidCredentialsException;
import com.nttdata.auth_service.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Controlador REST del flujo de autenticación (Parte III).
 * <p>
 * Implementa la interfaz {@link AuthApi} generada a partir del contrato OpenAPI
 * ({@code src/main/resources/openapi.yaml}), respetando el enfoque <i>contract-first</i>.
 * <p>
 * La reactividad se implementa con <b>RxJava 3</b> en la capa de servicio
 * ({@link AuthService} devuelve {@code Single}); en el borde HTTP esos tipos se adaptan a
 * Reactor (tipo declarado por la interfaz generada) con {@code Mono.from(...toFlowable())}.
 * Las credenciales inválidas se traducen a HTTP 401.
 *
 * @author NTT Data
 */
@Slf4j
@RestController
@RequiredArgsConstructor
public class AuthController implements AuthApi {

    private final AuthService authService;

    /**
     * {@code POST /auth/login} — autentica y emite un token JWT.
     *
     * @param loginRequest usuario y contraseña
     * @param exchange     contexto de la petición
     * @return respuesta 200 con el token, o 401 si las credenciales son inválidas
     */
    @Override
    public Mono<ResponseEntity<TokenResponse>> login(Mono<LoginRequest> loginRequest, ServerWebExchange exchange) {
        return loginRequest
                .flatMap(request -> Mono.from(authService.login(request).toFlowable()))
                .map(ResponseEntity::ok)
                .onErrorResume(InvalidCredentialsException.class,
                        ex -> Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()));
    }

    /**
     * {@code POST /auth/register} — registra un usuario para autenticación.
     *
     * @param registerRequest usuario, contraseña y rol opcional
     * @param exchange        contexto de la petición
     * @return respuesta 201 con el usuario creado
     */
    @Override
    public Mono<ResponseEntity<UserResponse>> register(Mono<RegisterRequest> registerRequest,
                                                       ServerWebExchange exchange) {
        return registerRequest
                .flatMap(request -> Mono.from(authService.register(request).toFlowable()))
                .map(response -> ResponseEntity.status(HttpStatus.CREATED).body(response));
    }
}
