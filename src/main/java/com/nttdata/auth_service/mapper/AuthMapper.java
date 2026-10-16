package com.nttdata.auth_service.mapper;

import com.nttdata.auth_service.dto.UserResponse;
import com.nttdata.auth_service.model.User;

/**
 * Conversor estático entre la entidad {@link User} y su DTO de respuesta
 * {@link UserResponse}. No expone nunca el hash de la contraseña.
 *
 * @author NTT Data
 */
public class AuthMapper {

    /** Clase de utilidad: no se instancia. */
    private AuthMapper() {
    }

    /**
     * Construye el DTO público del usuario.
     *
     * @param user entidad persistida
     * @return DTO con los datos públicos del usuario
     */
    public static UserResponse toResponse(User user) {
        UserResponse response = new UserResponse();
        response.setId(user.getId());
        response.setUsername(user.getUsername());
        response.setRole(user.getRole());
        return response;
    }
}
