package com.nttdata.auth_service.repository;

import com.nttdata.auth_service.model.User;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

/**
 * Repositorio reactivo de la colección {@code users} de MongoDB.
 * <p>
 * Se usan consultas derivadas de Spring Data (sin {@code @Query} ni SQL dinámico).
 *
 * @author NTT Data
 */
@Repository
public interface UserRepository extends ReactiveMongoRepository<User, String> {

    /**
     * Busca un usuario por su nombre de usuario.
     *
     * @param username nombre de usuario
     * @return {@code Mono} con el usuario, vacío si no existe
     */
    Mono<User> findByUsername(String username);

    /**
     * Comprueba si ya existe un usuario con ese nombre.
     *
     * @param username nombre de usuario
     * @return {@code Mono} con {@code true} si existe
     */
    Mono<Boolean> existsByUsername(String username);
}
