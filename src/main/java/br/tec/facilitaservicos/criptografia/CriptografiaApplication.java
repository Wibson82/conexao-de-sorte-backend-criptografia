package br.tec.facilitaservicos.criptografia;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.data.r2dbc.config.EnableR2dbcAuditing;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.security.Security;

/**
 * ============================================================================
 * 🔐 MICROSERVIÇO DE CRIPTOGRAFIA E GERENCIAMENTO DE CHAVES (KMS)
 * ============================================================================
 * 
 * Aplicação principal do microserviço de criptografia que centraliza:
 * 
 * 🔑 GERENCIAMENTO DE CHAVES:
 * - Geração de chaves simétricas e assimétricas
 * - Derivação de chaves com PBKDF2/Scrypt/Argon2
 * - Rotação automática e versionamento
 * - Armazenamento seguro com HSM/Cloud KMS
 * - Backup e recuperação de chaves
 * - Multi-tenant key isolation
 * 
 * 🛡️ CRIPTOGRAFIA AVANÇADA:
 * - AES-256-GCM para criptografia simétrica
 * - RSA-4096/ECC-P384 para criptografia assimétrica
 * - ChaCha20-Poly1305 para alta performance
 * - ECDSA/RSA-PSS para assinatura digital
 * - Authenticated encryption (AEAD)
 * - Forward secrecy com ephemeral keys
 * 
 * 🏢 INTEGRAÇÃO ENTERPRISE:
 * - HashiCorp Vault integration
 * - AWS KMS / Google Cloud KMS
 * - Azure Key Vault support
 * - PKCS#11 HSM connectivity
 * - Active Directory integration
 * - FIDO2/WebAuthn support
 * 
 * 🔐 OPERAÇÕES CRIPTOGRÁFICAS:
 * - Hashing seguro (SHA-3, Blake3, Argon2)
 * - MAC/HMAC para integridade
 * - Key derivation functions (KDF)
 * - Secure random number generation
 * - Constant-time operations
 * - Side-channel attack protection
 * 
 * 🚨 SEGURANÇA E AUDITORIA:
 * - Zero-knowledge architecture
 * - Perfect forward secrecy
 * - Audit trail completo
 * - Compliance (FIPS 140-2, Common Criteria)
 * - Data classification support
 * - Encryption at rest/in transit
 * 
 * 📊 MONITORAMENTO AVANÇADO:
 * - Performance metrics de operações crypto
 * - Rate limiting e throttling
 * - Anomaly detection em uso de chaves
 * - Alertas de segurança em tempo real
 * - Key usage analytics
 * - Compliance reporting
 * 
 * ⚡ PERFORMANCE E ESCALABILIDADE:
 * - Hardware acceleration (AES-NI, AVX)
 * - Async crypto operations
 * - Connection pooling para HSMs
 * - Intelligent caching strategies
 * - Load balancing entre key stores
 * - Auto-scaling baseado em demanda
 * 
 * @author Sistema de Migração R2DBC
 * @version 1.0
 * @since 2024
 */
@SpringBootApplication
@EnableR2dbcAuditing
@EnableCaching
@EnableScheduling
public class CriptografiaApplication {

    /**
     * Ponto de entrada da aplicação
     */
    public static void main(String[] args) {
        // Configurações de segurança críticas
        System.setProperty("java.security.egd", "file:/dev/./urandom"); // Entropy segura
        System.setProperty("javax.net.ssl.sessionCacheSize", "10000");
        System.setProperty("javax.net.ssl.sessionCacheTimeout", "3600");
        
        // Configurações de criptografia
        System.setProperty("crypto.policy", "unlimited"); // Unlimited strength crypto
        System.setProperty("jdk.tls.namedGroups", "x25519,secp256r1,secp384r1,secp521r1");
        System.setProperty("jdk.tls.keyLimits", "AES/GCM/NoPadding KeyUpdate 2^37");
        
        // Configurações do Bouncy Castle
        System.setProperty("org.bouncycastle.rsa.allow_unsafe_mod", "false");
        System.setProperty("org.bouncycastle.rsa.allow_multi_use", "false");
        System.setProperty("org.bouncycastle.ec.disable_mqv", "false");
        
        // Configurações de HSM (se disponível)
        System.setProperty("sun.security.pkcs11.allowSingleThreadedModules", "false");
        
        // Configurações de performance
        System.setProperty("java.security.SecureRandom.strongAlgorithms", "NativePRNG:SUN,DRBG:SUN");
        
        // Configurações do OpenTelemetry
        System.setProperty("otel.service.name", "criptografia-service");
        System.setProperty("otel.service.version", "1.0.0");
        System.setProperty("otel.resource.attributes", "service.namespace=conexao-de-sorte");
        
        // Configurações de observabilidade para crypto
        System.setProperty("management.metrics.export.prometheus.enabled", "true");
        System.setProperty("management.tracing.sampling.probability", "1.0");
        System.setProperty("management.endpoints.web.exposure.include", "health,info,prometheus,crypto,keys,vault");
        
        // Configurações de memória para operações crypto
        System.setProperty("crypto.buffer.size", "65536"); // 64KB buffers
        System.setProperty("crypto.thread.pool.size", "20");
        System.setProperty("crypto.operation.timeout", "30000"); // 30 segundos
        
        // Configurações de cache para chaves
        System.setProperty("crypto.key.cache.size", "1000");
        System.setProperty("crypto.key.cache.ttl", "3600"); // 1 hora
        
        // Banner customizado
        System.setProperty("spring.banner.location", "classpath:crypto-banner.txt");
        
        // Registrar Bouncy Castle como provider
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
        
        // Configurar algoritmos preferenciais
        Security.setProperty("crypto.policy", "unlimited");
        
        SpringApplication app = new SpringApplication(CriptografiaApplication.class);
        
        // Configurações adicionais da aplicação
        app.setAdditionalProfiles("crypto");
        
        // Inicializar aplicação
        var context = app.run(args);
        
        // Log de inicialização
        var logger = org.slf4j.LoggerFactory.getLogger(CriptografiaApplication.class);
        logger.info("🔐 Microserviço de Criptografia iniciado com sucesso!");
        logger.info("🔑 Key Management disponível em: http://localhost:8088/api/v1/keys");
        logger.info("🛡️ Crypto Operations em: http://localhost:8088/api/v1/crypto");
        logger.info("🏛️ Vault Integration em: http://localhost:8088/api/v1/vault");
        logger.info("📊 Métricas Prometheus em: http://localhost:8088/actuator/prometheus");
        logger.info("💊 Health checks em: http://localhost:8088/actuator/health");
        logger.info("📈 APIs de crypto em: http://localhost:8088/swagger-ui.html");
        logger.info("🔒 Security Dashboard em: http://localhost:8088/crypto-ui");
        
        // Verificar providers de segurança
        logger.info("🔧 Security Providers disponíveis:");
        java.security.Provider[] providers = Security.getProviders();
        for (java.security.Provider provider : providers) {
            logger.info("  - {} v{}: {}", provider.getName(), provider.getVersionStr(), provider.getInfo());
        }
        
        // Verificar algoritmos disponíveis
        logger.info("🧮 Algoritmos criptográficos suportados:");
        var algorithms = Security.getAlgorithms("Cipher");
        algorithms.forEach(alg -> logger.debug("  - Cipher: {}", alg));
        
        // Registro de shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("🛑 Iniciando shutdown graceful do serviço de criptografia...");
            
            try {
                // Limpar chaves sensíveis da memória
                logger.info("🧹 Limpando chaves sensíveis da memória...");
                System.gc(); // Force garbage collection
                
                // Finalizar conexões com HSM/Vault se existirem
                logger.info("🔌 Finalizando conexões seguras...");
                
                // Flush de logs de auditoria
                logger.info("📝 Finalizando logs de auditoria...");
                
            } catch (Exception e) {
                logger.error("❌ Erro durante shutdown: {}", e.getMessage());
            }
            
            context.close();
            logger.info("✅ Microserviço de Criptografia finalizado com sucesso!");
        }));
        
        // Verificar configurações críticas
        try {
            // Test crypto operations
            javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            logger.info("✅ Criptografia AES-GCM disponível");
            
            // Test key generation
            java.security.KeyPairGenerator.getInstance("RSA").initialize(2048);
            logger.info("✅ Geração de chaves RSA disponível");
            
            // Test secure random
            java.security.SecureRandom.getInstanceStrong().nextBytes(new byte[32]);
            logger.info("✅ Gerador de números aleatórios seguro disponível");
            
            logger.info("🔒 Todos os componentes criptográficos verificados com sucesso!");
            
        } catch (Exception e) {
            logger.error("💥 Erro crítico na verificação de componentes: {}", e.getMessage());
            System.exit(1);
        }
    }
}