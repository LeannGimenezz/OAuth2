package com.project.securityservice.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

//Indica que una clase proporciona metodos de configuracion reutilizables
@Configuration
//Habilita la seguridad web en la aplicacion
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Autowired
    private RsaKeysConfig rsaKeysConfig;


    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager(){
        return new InMemoryUserDetailsManager(
                User.withUsername("user")
                        .password("{noop}1234")
                        .authorities("USER")
                        .build(),
                User.withUsername("user1")
                        .password("{noop}1234")
                        .authorities("USER")
                        .build(),
                User.withUsername("user2")
                        .password("{noop}1234")
                        .authorities("USER","ADMIN")
                        .build()
        );
    }

    //DEFINE COMO SE FILTRA Y SE MANEJAN LAS PETICIONES HTTP
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((auth) ->
                        auth.anyRequest().authenticated()
                )//Configura la autorizacion de la aplicacion
                .oauth2ResourceServer((oauth2) ->
                        oauth2.jwt(Customizer.withDefaults())
                )//Configura el servidor de recursos OAuth2
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))//Lo que hace es especificar que se tiene que usar una politica de creacion de sesion sin estado, Spring security no almacena el estado de la sesion del usuario.
                .httpBasic(Customizer.withDefaults())//Se utiliza para configurar la autenticacion basica
                .build();
    }

    //Decodificar y validar tokens JWT
    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(rsaKeysConfig.publicKey()).build();
    }

    //Genera y firma los tokens JWT salientes
    @Bean
    JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(rsaKeysConfig.publicKey())
                .privateKey(rsaKeysConfig.privateKey())
                .build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);

    }
}
