package com.nttdata.auth_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Clase principal del microservicio de autenticación (auth-service).
 * <p>
 * Es un microservicio <b>nuevo</b> (Parte III): se construye a partir de su contrato
 * OpenAPI (contract-first) y devuelve tokens <b>JWT</b> firmados que el resto de
 * microservicios validan como <i>OAuth2 Resource Servers</i>.
 * <p>
 * Conforme al patrón database-per-service, gestiona su propia colección de usuarios
 * ({@code users}) y no accede a datos de otros microservicios; tampoco los invoca por
 * REST (restricción de la Parte III para microservicios nuevos).
 *
 * @author NTT Data
 */
@SpringBootApplication
public class AuthServiceApplication {

	/**
	 * Punto de entrada de la aplicación Spring Boot.
	 *
	 * @param args argumentos de línea de comandos proporcionados al arrancar
	 */
	public static void main(String[] args) {
		SpringApplication.run(AuthServiceApplication.class, args);
	}

}
