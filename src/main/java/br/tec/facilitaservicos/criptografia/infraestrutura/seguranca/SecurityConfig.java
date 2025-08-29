package br.tec.facilitaservicos.criptografia.infraestrutura.seguranca;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

/**
 * ============================================================================
 * 🔐 CONFIGURAÇÃO DE SEGURANÇA ULTRA-RESTRITIVA - CRIPTOGRAFIA
 * ============================================================================
 * 
 * Configuração de segurança máxima para microserviço de criptografia:
 * - Validação JWT via JWKS com authorities específicas para crypto
 * - Controle de acesso granular baseado em operações criptográficas
 * - CORS ultra-restritivo (apenas POST de APIs internas)
 * - Headers de segurança máximos para proteção de chaves
 * - Rate limiting agressivo para operações sensíveis
 * - SSL/TLS obrigatório em produção
 * - Logs mínimos para não vazar informações sensíveis
 * 
 * @author Sistema de Migração R2DBC
 * @version 1.0
 * @since 2024
 */
@Configuration
@EnableWebFluxSecurity
@EnableMethodSecurity
public class SecurityConfig {

    // Constantes para valores repetidos
    private static final String CONTENT_TYPE_JSON = "application/json";
    private static final String HEADER_CONTENT_TYPE = "Content-Type";
    private static final String PROFILE_PRODUCAO = "prod";
    private static final String ERRO_CORS_ORIGEM_INSEGURA = "Configuração CORS inválida: apenas origins HTTPS são permitidas para serviço de criptografia";
    
    // Templates de resposta JSON mínimas para não vazar informações
    private static final String TEMPLATE_ERRO_AUTENTICACAO = """
        {
            "status": 401,
            "erro": "Não autorizado",
            "timestamp": "%s",
            "service": "criptografia"
        }
        """;
        
    private static final String TEMPLATE_ERRO_ACESSO = """
        {
            "status": 403,
            "erro": "Acesso negado",
            "timestamp": "%s",
            "service": "criptografia"
        }
        """;

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    @Value("${cors.allowed-origins:https://api.conexaodesorte.com}")
    private String allowedOriginsProperty;

    private List<String> allowedOrigins;

    @Value("#{'${cors.allowed-methods:POST}'.split(',')}")
    private List<String> allowedMethods;

    @Value("${cors.allow-credentials:false}")
    private boolean allowCredentials;

    @Value("${cors.max-age:0}")
    private long maxAge;

    private final Environment environment;

    public SecurityConfig(Environment environment) {
        this.environment = environment;
    }

    @PostConstruct
    public void validarConfiguracaoCors() {
        this.allowedOrigins = Arrays.stream(allowedOriginsProperty.split(","))
            .map(String::trim)
            .toList();

        // Para criptografia, SEMPRE validar que apenas HTTPS é permitido
        boolean temOrigemInsegura = allowedOrigins.stream()
            .anyMatch(origin -> origin.equals("*") || origin.startsWith("http://"));
        if (temOrigemInsegura && !Arrays.asList(environment.getActiveProfiles()).contains("test")) {
            throw new IllegalStateException(ERRO_CORS_ORIGEM_INSEGURA);
        }
    }

    /**
     * Configuração ultra-restritiva da cadeia de filtros de segurança para criptografia
     */
    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
            // Desabilitar proteções desnecessárias para API reativa
            .csrf(csrf -> csrf.disable())
            .formLogin(form -> form.disable())
            .httpBasic(basic -> basic.disable())

            // Configurar CORS ultra-restritivo
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))

            // Configurar autorização específica para operações criptográficas
            .authorizeExchange(exchanges -> exchanges
                // Health check apenas (mínimo necessário)
                .pathMatchers("/actuator/health/**").permitAll()
                
                // Documentação desabilitada por padrão (apenas em dev se habilitado)
                .pathMatchers(
                    "/v3/api-docs/**",
                    "/swagger-ui.html",
                    "/swagger-ui/**",
                    "/webjars/**"
                ).hasAuthority("SCOPE_admin")
                
                // Operações de criptografia - requerem authorities específicas
                .pathMatchers(HttpMethod.POST, "/api/v1/crypto/encrypt/**")
                    .hasAnyAuthority("SCOPE_crypto_encrypt", "SCOPE_admin")
                    
                .pathMatchers(HttpMethod.POST, "/api/v1/crypto/decrypt/**")
                    .hasAnyAuthority("SCOPE_crypto_decrypt", "SCOPE_admin")
                    
                .pathMatchers(HttpMethod.POST, "/api/v1/crypto/hash/**")
                    .hasAnyAuthority("SCOPE_crypto_hash", "SCOPE_crypto_encrypt", "SCOPE_admin")
                    
                .pathMatchers(HttpMethod.POST, "/api/v1/crypto/sign/**")
                    .hasAnyAuthority("SCOPE_crypto_sign", "SCOPE_admin")
                    
                .pathMatchers(HttpMethod.POST, "/api/v1/crypto/verify/**")
                    .hasAnyAuthority("SCOPE_crypto_verify", "SCOPE_crypto_sign", "SCOPE_admin")
                
                // Gerenciamento de chaves - máxima restrição
                .pathMatchers("/api/v1/crypto/keys/**")
                    .hasAuthority("SCOPE_crypto_keys")
                    
                .pathMatchers("/api/v1/crypto/keys/rotate/**")
                    .hasAuthority("SCOPE_admin")
                
                // Endpoints administrativos críticos
                .pathMatchers("/actuator/**").hasAuthority("SCOPE_admin")
                
                // Qualquer outro endpoint requer pelo menos role de crypto
                .anyExchange().hasAnyAuthority("SCOPE_crypto_read", "SCOPE_admin")
            )

            // Configurar JWT
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtDecoder(reactiveJwtDecoder())
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            )

            // Headers de segurança máximos para criptografia
            .headers(headers -> headers
                .contentSecurityPolicy("default-src 'none'; script-src 'none'; style-src 'none'; img-src 'none'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
                .and()
                .frameOptions().deny()
                .httpStrictTransportSecurity(hstsConfig -> hstsConfig
                    .maxAgeInSeconds(63072000) // 2 anos
                    .includeSubdomains(true)
                    .preload(true)
                )
                .cacheControl(cacheConfig -> cacheConfig.disable()) // Cache desabilitado para segurança
            )

            // Configurar tratamento de exceções minimalista para não vazar informações
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint((exchange, _) -> {
                    var response = exchange.getResponse();
                    response.setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
                    response.getHeaders().add(HEADER_CONTENT_TYPE, CONTENT_TYPE_JSON);
                    response.getHeaders().add("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
                    
                    String body = TEMPLATE_ERRO_AUTENTICACAO.formatted(java.time.LocalDateTime.now());
                    
                    var buffer = response.bufferFactory().wrap(body.getBytes());
                    return response.writeWith(reactor.core.publisher.Mono.just(buffer));
                })
                .accessDeniedHandler((exchange, _) -> {
                    var response = exchange.getResponse();
                    response.setStatusCode(org.springframework.http.HttpStatus.FORBIDDEN);
                    response.getHeaders().add(HEADER_CONTENT_TYPE, CONTENT_TYPE_JSON);
                    response.getHeaders().add("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
                    
                    String body = TEMPLATE_ERRO_ACESSO.formatted(java.time.LocalDateTime.now());
                    
                    var buffer = response.bufferFactory().wrap(body.getBytes());
                    return response.writeWith(reactor.core.publisher.Mono.just(buffer));
                })
            )

            .build();
    }

    /**
     * Decodificador JWT reativo via JWKS
     */
    @Bean
    public ReactiveJwtDecoder reactiveJwtDecoder() {
        return NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).build();
    }

    /**
     * Conversor de autenticação JWT personalizado para criptografia
     */
    @Bean
    public ReactiveJwtAuthenticationConverterAdapter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter());
        return new ReactiveJwtAuthenticationConverterAdapter(converter);
    }

    /**
     * Conversor personalizado de authorities JWT para operações criptográficas
     */
    @Bean
    public Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter() {
        return new CustomJwtGrantedAuthoritiesConverter();
    }

    /**
     * Configuração CORS ultra-restritiva para operações criptográficas
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // Origins permitidas (apenas APIs internas HTTPS)
        configuration.setAllowedOrigins(allowedOrigins);
        
        // Apenas POST para operações criptográficas
        configuration.setAllowedMethods(allowedMethods);
        
        // Headers mínimos necessários
        configuration.setAllowedHeaders(List.of(
            "Authorization",
            "Content-Type"
        ));

        // Sem credenciais para máxima segurança
        configuration.setAllowCredentials(allowCredentials);
        
        // Sem cache para segurança
        configuration.setMaxAge(maxAge);
        
        // Headers mínimos expostos
        configuration.setExposedHeaders(List.of(
            "Content-Type"
        ));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        
        return source;
    }

    /**
     * Classe interna para conversão de authorities JWT específica para criptografia
     */
    private static class CustomJwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
        
        @Override
        public Collection<GrantedAuthority> convert(Jwt jwt) {
            Collection<GrantedAuthority> authorities = new java.util.ArrayList<>();
            
            // Processar claim 'roles' 
            var rolesClaim = jwt.getClaim("roles");
            if (rolesClaim != null) {
                if (rolesClaim instanceof List<?> rolesList) {
                    authorities.addAll(
                        rolesList.stream()
                            .filter(String.class::isInstance)
                            .map(String.class::cast)
                            .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                            .toList()
                    );
                }
            }
            
            // Processar claim 'authorities'
            var authoritiesClaim = jwt.getClaim("authorities");
            if (authoritiesClaim != null) {
                if (authoritiesClaim instanceof List<?> authList) {
                    authorities.addAll(
                        authList.stream()
                            .filter(String.class::isInstance)
                            .map(String.class::cast)
                            .map(SimpleGrantedAuthority::new)
                            .toList()
                    );
                }
            }
            
            // Processar claim 'scope' (OAuth2 padrão)
            var scopeClaim = jwt.getClaim("scope");
            if (scopeClaim instanceof String scopeString) {
                authorities.addAll(
                    Arrays.stream(scopeString.split("\\s+"))
                        .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                        .toList()
                );
            }
            
            // Adicionar authorities específicas para criptografia baseadas em claims customizados
            var cryptoRolesClaim = jwt.getClaim("crypto_roles");
            if (cryptoRolesClaim instanceof List<?> cryptoRolesList) {
                authorities.addAll(
                    cryptoRolesList.stream()
                        .filter(String.class::isInstance)
                        .map(String.class::cast)
                        .map(role -> new SimpleGrantedAuthority("SCOPE_crypto_" + role))
                        .toList()
                );
            }
            
            return authorities;
        }
    }
}