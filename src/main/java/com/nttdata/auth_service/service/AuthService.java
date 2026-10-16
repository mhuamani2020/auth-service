package com.nttdata.auth_service.service;

import com.nttdata.auth_service.dto.LoginRequest;
import com.nttdata.auth_service.dto.RegisterRequest;
import com.nttdata.auth_service.dto.TokenResponse;
import com.nttdata.auth_service.dto.UserResponse;
import io.reactivex.rxjava3.core.Single;

/**
 * Servicio de autenticación y registro de usuarios (Parte III).
 * <p>
 * Al tratarse de una <b>nueva funcionalidad</b>, la capa de servicio se implementa con el
 * modelo de reactividad de <b>RxJava 3</b> ({@link Single}); el controlador, fiel al enfoque
 * <i>contract-first</i>, implementa la interfaz generada desde el contrato OpenAPI y adapta
 * estos tipos a Reactor en el borde HTTP.
 *
 * @author NTT Data
 */
public interface AuthService {

    /**
     * Autentica un usuario y emite un token JWT si las credenciales son válidas.
     *
     * @param request usuario y contraseña
     * @return {@code Single} con el token JWT
     */
    Single<TokenResponse> login(LoginRequest request);

    /**
     * Registra un nuevo usuario para autenticación.
     *
     * @param request usuario, contraseña y rol opcional
     * @return {@code Single} con el usuario creado
     */
    Single<UserResponse> register(RegisterRequest request);
}
