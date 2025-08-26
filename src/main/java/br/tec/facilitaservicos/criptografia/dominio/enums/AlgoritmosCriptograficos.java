package br.tec.facilitaservicos.criptografia.dominio.enums;

/**
 * ============================================================================
 * 🔐 ALGORITMOS CRIPTOGRÁFICOS SUPORTADOS
 * ============================================================================
 * 
 * Enum que define os algoritmos criptográficos suportados pelo sistema:
 * - Criptografia simétrica para dados em massa
 * - Criptografia assimétrica para troca de chaves
 * - Algoritmos de hash para integridade
 * - Algoritmos de MAC para autenticação
 * - Key derivation functions
 * - Assinatura digital
 * 
 * Cada algoritmo tem configurações específicas:
 * - Tamanho de chave recomendado
 * - Força de segurança
 * - Performance relativa
 * - Casos de uso apropriados
 * 
 * @author Sistema de Migração R2DBC
 * @version 1.0
 * @since 2024
 */
public enum AlgoritmosCriptograficos {

    // === CRIPTOGRAFIA SIMÉTRICA ===
    
    /**
     * AES-256-GCM - Padrão ouro para criptografia simétrica
     * - Authenticated encryption (confidencialidade + integridade)
     * - Hardware acceleration disponível
     * - Parallelizable
     */
    AES_256_GCM("AES/GCM/NoPadding", 256, 128, TipoCriptografia.SIMETRICA, 
                "AES-256 com Galois/Counter Mode", true, true, 95),
    
    /**
     * AES-128-GCM - Versão mais rápida para casos menos críticos
     */
    AES_128_GCM("AES/GCM/NoPadding", 128, 128, TipoCriptografia.SIMETRICA,
                "AES-128 com Galois/Counter Mode", true, true, 90),
    
    /**
     * ChaCha20-Poly1305 - Alternativa moderna ao AES
     * - Excelente performance em software
     * - Resistente a ataques de timing
     * - Authenticated encryption
     */
    CHACHA20_POLY1305("ChaCha20-Poly1305", 256, 128, TipoCriptografia.SIMETRICA,
                      "ChaCha20 stream cipher com Poly1305 MAC", true, false, 92),
    
    /**
     * AES-256-CTR - Counter mode para aplicações específicas
     */
    AES_256_CTR("AES/CTR/NoPadding", 256, 0, TipoCriptografia.SIMETRICA,
                "AES-256 Counter Mode", false, true, 85),

    // === CRIPTOGRAFIA ASSIMÉTRICA ===
    
    /**
     * RSA-4096 - RSA de alta segurança
     */
    RSA_4096("RSA", 4096, 0, TipoCriptografia.ASSIMETRICA,
             "RSA com chave de 4096 bits", false, false, 70),
    
    /**
     * RSA-2048 - RSA padrão
     */
    RSA_2048("RSA", 2048, 0, TipoCriptografia.ASSIMETRICA,
             "RSA com chave de 2048 bits", false, false, 75),
    
    /**
     * ECDSA-P384 - Curva elíptica de alta segurança
     */
    ECDSA_P384("ECDSA", 384, 0, TipoCriptografia.ASSIMETRICA,
               "ECDSA com curva P-384", false, false, 90),
    
    /**
     * ECDSA-P256 - Curva elíptica padrão
     */
    ECDSA_P256("ECDSA", 256, 0, TipoCriptografia.ASSIMETRICA,
               "ECDSA com curva P-256", false, false, 85),
    
    /**
     * Ed25519 - Curva moderna para assinatura
     */
    ED25519("Ed25519", 255, 0, TipoCriptografia.ASSIMETRICA,
            "EdDSA com Curve25519", false, false, 95),

    // === ALGORITMOS DE HASH ===
    
    /**
     * SHA3-256 - Hash de nova geração
     */
    SHA3_256("SHA3-256", 256, 0, TipoCriptografia.HASH,
             "SHA-3 com output de 256 bits", false, false, 90),
    
    /**
     * SHA-256 - Hash padrão
     */
    SHA_256("SHA-256", 256, 0, TipoCriptografia.HASH,
            "SHA-2 com output de 256 bits", false, true, 85),
    
    /**
     * Blake3 - Hash de alta performance
     */
    BLAKE3("Blake3", 256, 0, TipoCriptografia.HASH,
           "Blake3 hash function", false, false, 95),

    // === MESSAGE AUTHENTICATION CODE ===
    
    /**
     * HMAC-SHA256 - HMAC com SHA-256
     */
    HMAC_SHA256("HmacSHA256", 256, 0, TipoCriptografia.MAC,
                "HMAC com SHA-256", false, true, 85),
    
    /**
     * HMAC-SHA3-256 - HMAC com SHA3-256
     */
    HMAC_SHA3_256("HmacSHA3-256", 256, 0, TipoCriptografia.MAC,
                  "HMAC com SHA3-256", false, false, 90),

    // === KEY DERIVATION FUNCTIONS ===
    
    /**
     * PBKDF2 - Password-Based Key Derivation Function 2
     */
    PBKDF2("PBKDF2WithHmacSHA256", 256, 0, TipoCriptografia.KDF,
           "PBKDF2 com HMAC-SHA256", false, true, 70),
    
    /**
     * Scrypt - Memory-hard KDF
     */
    SCRYPT("Scrypt", 256, 0, TipoCriptografia.KDF,
           "Scrypt key derivation", false, false, 85),
    
    /**
     * Argon2id - Vencedor do Password Hashing Competition
     */
    ARGON2ID("Argon2id", 256, 0, TipoCriptografia.KDF,
             "Argon2id (hybrid)", false, false, 95);

    private final String javaAlgorithm;
    private final int keySize;
    private final int tagSize;
    private final TipoCriptografia tipo;
    private final String descricao;
    private final boolean authenticatedEncryption;
    private final boolean hardwareAcceleration;
    private final int securityScore;

    AlgoritmosCriptograficos(String javaAlgorithm, int keySize, int tagSize,
                           TipoCriptografia tipo, String descricao, 
                           boolean authenticatedEncryption, boolean hardwareAcceleration,
                           int securityScore) {
        this.javaAlgorithm = javaAlgorithm;
        this.keySize = keySize;
        this.tagSize = tagSize;
        this.tipo = tipo;
        this.descricao = descricao;
        this.authenticatedEncryption = authenticatedEncryption;
        this.hardwareAcceleration = hardwareAcceleration;
        this.securityScore = securityScore;
    }

    // === MÉTODOS DE CLASSIFICAÇÃO ===

    /**
     * Verifica se é criptografia simétrica
     */
    public boolean isSimetrica() {
        return tipo == TipoCriptografia.SIMETRICA;
    }

    /**
     * Verifica se é criptografia assimétrica
     */
    public boolean isAssimetrica() {
        return tipo == TipoCriptografia.ASSIMETRICA;
    }

    /**
     * Verifica se é algoritmo de hash
     */
    public boolean isHash() {
        return tipo == TipoCriptografia.HASH;
    }

    /**
     * Verifica se é MAC
     */
    public boolean isMac() {
        return tipo == TipoCriptografia.MAC;
    }

    /**
     * Verifica se é KDF
     */
    public boolean isKdf() {
        return tipo == TipoCriptografia.KDF;
    }

    /**
     * Verifica se suporta authenticated encryption
     */
    public boolean isAuthenticatedEncryption() {
        return authenticatedEncryption;
    }

    /**
     * Verifica se tem aceleração de hardware
     */
    public boolean hasHardwareAcceleration() {
        return hardwareAcceleration;
    }

    /**
     * Verifica se é algoritmo de alta segurança (score >= 90)
     */
    public boolean isHighSecurity() {
        return securityScore >= 90;
    }

    /**
     * Verifica se é adequado para dados críticos
     */
    public boolean isSuitableForCriticalData() {
        return securityScore >= 85 && (isSimetrica() ? authenticatedEncryption : true);
    }

    // === RECOMENDAÇÕES POR USO ===

    /**
     * Obtém algoritmo recomendado para criptografia de dados
     */
    public static AlgoritmosCriptograficos getRecommendedForDataEncryption() {
        return AES_256_GCM;
    }

    /**
     * Obtém algoritmo recomendado para assinatura digital
     */
    public static AlgoritmosCriptograficos getRecommendedForDigitalSignature() {
        return ED25519;
    }

    /**
     * Obtém algoritmo recomendado para hash
     */
    public static AlgoritmosCriptograficos getRecommendedForHashing() {
        return SHA3_256;
    }

    /**
     * Obtém algoritmo recomendado para derivação de senha
     */
    public static AlgoritmosCriptograficos getRecommendedForPasswordDerivation() {
        return ARGON2ID;
    }

    /**
     * Obtém algoritmo recomendado para alta performance
     */
    public static AlgoritmosCriptograficos getRecommendedForHighPerformance() {
        return CHACHA20_POLY1305;
    }

    // === CONFIGURAÇÕES ESPECÍFICAS ===

    /**
     * Obtém tamanho do IV/nonce em bytes
     */
    public int getIvSize() {
        return switch (this) {
            case AES_256_GCM, AES_128_GCM -> 12; // 96 bits
            case CHACHA20_POLY1305 -> 12; // 96 bits
            case AES_256_CTR -> 16; // 128 bits
            default -> 0;
        };
    }

    /**
     * Obtém tamanho do salt recomendado em bytes
     */
    public int getRecommendedSaltSize() {
        return switch (this) {
            case PBKDF2, SCRYPT, ARGON2ID -> 32; // 256 bits
            default -> 16; // 128 bits
        };
    }

    /**
     * Obtém número de iterações recomendado para KDF
     */
    public int getRecommendedIterations() {
        return switch (this) {
            case PBKDF2 -> 100000;
            case SCRYPT -> 32768;
            case ARGON2ID -> 3;
            default -> 1;
        };
    }

    /**
     * Obtém parâmetros específicos do algoritmo
     */
    public AlgorithmParameters getAlgorithmParameters() {
        return switch (this) {
            case SCRYPT -> new AlgorithmParameters(32768, 8, 1); // N, r, p
            case ARGON2ID -> new AlgorithmParameters(3, 65536, 4); // iterations, memory KB, parallelism
            default -> new AlgorithmParameters(getRecommendedIterations(), 0, 0);
        };
    }

    /**
     * Busca algoritmo por nome Java
     */
    public static AlgoritmosCriptograficos fromJavaAlgorithm(String algorithm) {
        for (AlgoritmosCriptograficos algo : values()) {
            if (algo.javaAlgorithm.equals(algorithm)) {
                return algo;
            }
        }
        throw new IllegalArgumentException("Algoritmo não suportado: " + algorithm);
    }

    /**
     * Obtém todos os algoritmos de um tipo
     */
    public static AlgoritmosCriptograficos[] getByType(TipoCriptografia tipo) {
        return java.util.Arrays.stream(values())
            .filter(algo -> algo.tipo == tipo)
            .toArray(AlgoritmosCriptograficos[]::new);
    }

    /**
     * Obtém algoritmos com aceleração de hardware
     */
    public static AlgoritmosCriptograficos[] getHardwareAccelerated() {
        return java.util.Arrays.stream(values())
            .filter(AlgoritmosCriptograficos::hasHardwareAcceleration)
            .toArray(AlgoritmosCriptograficos[]::new);
    }

    // === GETTERS ===

    public String getJavaAlgorithm() {
        return javaAlgorithm;
    }

    public int getKeySize() {
        return keySize;
    }

    public int getTagSize() {
        return tagSize;
    }

    public TipoCriptografia getTipo() {
        return tipo;
    }

    public String getDescricao() {
        return descricao;
    }

    public int getSecurityScore() {
        return securityScore;
    }

    public int getKeySizeInBytes() {
        return keySize / 8;
    }

    public int getTagSizeInBytes() {
        return tagSize / 8;
    }

    @Override
    public String toString() {
        return String.format("%s (%s - %d bits)", name(), descricao, keySize);
    }

    // === CLASSES AUXILIARES ===

    /**
     * Tipo de criptografia
     */
    public enum TipoCriptografia {
        SIMETRICA("Criptografia Simétrica"),
        ASSIMETRICA("Criptografia Assimétrica"),
        HASH("Função Hash"),
        MAC("Message Authentication Code"),
        KDF("Key Derivation Function");

        private final String descricao;

        TipoCriptografia(String descricao) {
            this.descricao = descricao;
        }

        public String getDescricao() {
            return descricao;
        }
    }

    /**
     * Parâmetros específicos do algoritmo
     */
    public static class AlgorithmParameters {
        private final int param1;
        private final int param2;
        private final int param3;

        public AlgorithmParameters(int param1, int param2, int param3) {
            this.param1 = param1;
            this.param2 = param2;
            this.param3 = param3;
        }

        public int getParam1() { return param1; }
        public int getParam2() { return param2; }
        public int getParam3() { return param3; }
    }
}