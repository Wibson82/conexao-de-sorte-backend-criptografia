package br.tec.facilitaservicos.criptografia.infraestrutura.web;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.tec.facilitaservicos.criptografia.aplicacao.servico.CryptographyService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import reactor.core.publisher.Mono;

/**
 * ============================================================================
 * 🔐 CONTROLLER REATIVO DE CRIPTOGRAFIA
 * ============================================================================
 * 
 * Controller 100% reativo para operações criptográficas seguras:
 * - Criptografia simétrica e assimétrica
 * - Hash e verificação de integridade
 * - Assinatura digital e verificação
 * - Gerenciamento seguro de chaves
 * 
 * Endpoints (todos via POST por segurança):
 * - POST /api/v1/crypto/encrypt - Criptografar dados
 * - POST /api/v1/crypto/decrypt - Descriptografar dados
 * - POST /api/v1/crypto/hash - Gerar hash
 * - POST /api/v1/crypto/sign - Assinar digitalmente
 * - POST /api/v1/crypto/verify - Verificar assinatura
 * - POST /api/v1/crypto/keys/generate - Gerar nova chave
 * 
 * @author Sistema de Migração R2DBC
 * @version 1.0
 * @since 2024
 */
@RestController
@RequestMapping("/api/v1/crypto")
@Tag(name = "Criptografia", description = "API para operações criptográficas seguras")
@SecurityRequirement(name = "bearerAuth")
public class CriptografiaController {

    private final CryptographyService cryptographyService;

    public CriptografiaController(CryptographyService cryptographyService) {
        this.cryptographyService = cryptographyService;
    }

    /**
     * Criptografar dados sensíveis
     */
    @PostMapping("/encrypt")
    @PreAuthorize("hasAuthority('SCOPE_crypto_encrypt') or hasAuthority('SCOPE_admin')")
    @Operation(summary = "Criptografar dados", description = "Criptografa dados usando algoritmos seguros")
    public Mono<ResponseEntity<Map<String, Object>>> encrypt(
            @Valid @RequestBody Map<String, Object> request,
            Authentication authentication) {
        
        String data = (String) request.get("data");
        String algorithm = (String) request.getOrDefault("algorithm", "AES-256-GCM");
        String keyId = (String) request.get("keyId");
        
        return cryptographyService.encrypt(data, algorithm, keyId, authentication.getName())
                .map(result -> ResponseEntity.ok(Map.of(
                    "encryptedData", result.get("encryptedData"),
                    "keyId", result.get("keyId"),
                    "algorithm", algorithm,
                    "timestamp", java.time.LocalDateTime.now()
                )));
    }

    /**
     * Descriptografar dados
     */
    @PostMapping("/decrypt")
    @PreAuthorize("hasAuthority('SCOPE_crypto_decrypt') or hasAuthority('SCOPE_admin')")
    @Operation(summary = "Descriptografar dados", description = "Descriptografa dados previamente criptografados")
    public Mono<ResponseEntity<Map<String, Object>>> decrypt(
            @Valid @RequestBody Map<String, Object> request,
            Authentication authentication) {
        
        String encryptedData = (String) request.get("encryptedData");
        String keyId = (String) request.get("keyId");
        
        return cryptographyService.decrypt(encryptedData, keyId, authentication.getName())
                .map(result -> ResponseEntity.ok(Map.of(
                    "decryptedData", result.get("decryptedData"),
                    "timestamp", java.time.LocalDateTime.now()
                )));
    }

    /**
     * Gerar hash seguro
     */
    @PostMapping("/hash")
    @PreAuthorize("hasAuthority('SCOPE_crypto_hash') or hasAuthority('SCOPE_crypto_encrypt') or hasAuthority('SCOPE_admin')")
    @Operation(summary = "Gerar hash", description = "Gera hash seguro dos dados fornecidos")
    public Mono<ResponseEntity<Map<String, Object>>> hash(
            @Valid @RequestBody Map<String, Object> request,
            Authentication authentication) {
        
        String data = (String) request.get("data");
        String algorithm = (String) request.getOrDefault("algorithm", "SHA-256");
        String salt = (String) request.get("salt");
        
        return cryptographyService.hash(data, algorithm, salt, authentication.getName())
                .map(result -> ResponseEntity.ok(Map.of(
                    "hash", result.get("hash"),
                    "algorithm", algorithm,
                    "salt", result.get("salt"),
                    "timestamp", java.time.LocalDateTime.now()
                )));
    }

    /**
     * Assinar dados digitalmente
     */
    @PostMapping("/sign")
    @PreAuthorize("hasAuthority('SCOPE_crypto_sign') or hasAuthority('SCOPE_admin')")
    @Operation(summary = "Assinar digitalmente", description = "Cria assinatura digital dos dados")
    public Mono<ResponseEntity<Map<String, Object>>> sign(
            @Valid @RequestBody Map<String, Object> request,
            Authentication authentication) {
        
        String data = (String) request.get("data");
        String keyId = (String) request.get("keyId");
        String algorithm = (String) request.getOrDefault("algorithm", "RSA-SHA256");
        
        return cryptographyService.sign(data, keyId, algorithm, authentication.getName())
                .map(result -> ResponseEntity.ok(Map.of(
                    "signature", result.get("signature"),
                    "keyId", keyId,
                    "algorithm", algorithm,
                    "timestamp", java.time.LocalDateTime.now()
                )));
    }

    /**
     * Verificar assinatura digital
     */
    @PostMapping("/verify")
    @PreAuthorize("hasAuthority('SCOPE_crypto_verify') or hasAuthority('SCOPE_crypto_sign') or hasAuthority('SCOPE_admin')")
    @Operation(summary = "Verificar assinatura", description = "Verifica a validade de uma assinatura digital")
    public Mono<ResponseEntity<Map<String, Object>>> verify(
            @Valid @RequestBody Map<String, Object> request,
            Authentication authentication) {
        
        String data = (String) request.get("data");
        String signature = (String) request.get("signature");
        String keyId = (String) request.get("keyId");
        
        return cryptographyService.verify(data, signature, keyId, authentication.getName())
                .map(result -> ResponseEntity.ok(Map.of(
                    "valid", result.get("valid"),
                    "keyId", keyId,
                    "timestamp", java.time.LocalDateTime.now()
                )));
    }

    /**
     * Gerar nova chave criptográfica
     */
    @PostMapping("/keys/generate")
    @PreAuthorize("hasAuthority('SCOPE_crypto_keys') or hasAuthority('SCOPE_admin')")
    @Operation(summary = "Gerar chave", description = "Gera nova chave criptográfica segura")
    public Mono<ResponseEntity<Map<String, Object>>> generateKey(
            @Valid @RequestBody Map<String, Object> request,
            Authentication authentication) {
        
        String keyType = (String) request.getOrDefault("keyType", "AES");
        Integer keySize = (Integer) request.getOrDefault("keySize", 256);
        String purpose = (String) request.getOrDefault("purpose", "ENCRYPT_DECRYPT");
        
        return cryptographyService.generateKey(keyType, keySize, purpose, authentication.getName())
                .map(result -> ResponseEntity.ok(Map.of(
                    "keyId", result.get("keyId"),
                    "keyType", keyType,
                    "keySize", keySize,
                    "purpose", purpose,
                    "timestamp", java.time.LocalDateTime.now()
                )));
    }

    /**
     * Rotacionar chave existente
     */
    @PostMapping("/keys/rotate")
    @PreAuthorize("hasAuthority('SCOPE_admin')")
    @Operation(summary = "Rotacionar chave", description = "Rotaciona uma chave existente mantendo compatibilidade")
    public Mono<ResponseEntity<Map<String, Object>>> rotateKey(
            @Valid @RequestBody Map<String, Object> request,
            Authentication authentication) {
        
        String keyId = (String) request.get("keyId");
        
        return cryptographyService.rotateKey(keyId, authentication.getName())
                .map(result -> ResponseEntity.ok(Map.of(
                    "oldKeyId", keyId,
                    "newKeyId", result.get("newKeyId"),
                    "rotationTimestamp", java.time.LocalDateTime.now()
                )));
    }
}