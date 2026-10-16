package com.nttdata.auth_service.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * Usuario del sistema con credenciales para autenticación.
 * <p>
 * Colección propia de {@code auth-service} ({@code users}), en cumplimiento del patrón
 * <i>database per service</i>: ningún otro microservicio accede a ella. La contraseña se
 * almacena siempre cifrada (BCrypt), nunca en texto plano.
 *
 * @author NTT Data
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Document(collection = "users")
public class User {

    /** Identificador autogenerado del usuario. */
    @Id
    private String id;

    /** Nombre de usuario único. */
    private String username;

    /** Contraseña cifrada (hash BCrypt). */
    private String password;

    /** Rol del usuario ({@code ADMIN}, {@code USER}); base de la autorización. */
    private String role;
}
