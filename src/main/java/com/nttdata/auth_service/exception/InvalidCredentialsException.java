package com.nttdata.auth_service.exception;

/**
 * Excepción de dominio que representa credenciales inválidas en el inicio de sesión.
 * <p>
 * El controlador la traduce a HTTP 401 (no autorizado), diferenciándola de los errores
 * de validación ({@link IllegalArgumentException} → HTTP 400).
 *
 * @author NTT Data
 */
public class InvalidCredentialsException extends RuntimeException {

    /**
     * Crea la excepción con un mensaje descriptivo.
     *
     * @param message mensaje del error
     */
    public InvalidCredentialsException(String message) {
        super(message);
    }
}
