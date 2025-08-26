package br.tec.facilitaservicos.criptografia.dominio.enums;

/**
 * ============================================================================
 * 🗝️ TIPOS DE CHAVES CRIPTOGRÁFICAS
 * ============================================================================
 * 
 * Enum que define os diferentes tipos de chaves criptográficas:
 * - Chaves simétricas para criptografia rápida
 * - Chaves assimétricas para troca segura
 * - Chaves derivadas de senha
 * - Chaves temporárias (ephemeral)
 * - Chaves de sessão
 * - Chaves mestras
 * 
 * Cada tipo tem características específicas:
 * - Tamanhos de chave suportados
 * - Algoritmos compatíveis
 * - Casos de uso apropriados
 * - Políticas de rotação
 * - Níveis de proteção
 * 
 * @author Sistema de Migração R2DBC
 * @version 1.0
 * @since 2024
 */
public enum TipoChave {

    // === CHAVES SIMÉTRICAS ===
    
    /**
     * Chave de criptografia de dados (DEK - Data Encryption Key)
     * - Usada para criptografar dados de aplicação
     * - Geralmente 256 bits
     * - Rotação frequente recomendada
     */
    DATA_ENCRYPTION("dek", "Data Encryption Key", 
                    "Chave simétrica para criptografia de dados",
                    new int[]{128, 256}, true, false, 30, 
                    new String[]{"AES_256_GCM", "CHACHA20_POLY1305"}),
    
    /**
     * Chave de criptografia de chaves (KEK - Key Encryption Key)
     * - Usada para criptografar outras chaves
     * - Mais duradoura que DEKs
     * - Proteção adicional requerida
     */
    KEY_ENCRYPTION("kek", "Key Encryption Key",
                   "Chave simétrica para criptografia de chaves",
                   new int[]{256}, true, false, 90,
                   new String[]{"AES_256_GCM"}),
    
    /**
     * Chave mestra (MEK - Master Encryption Key)
     * - Topo da hierarquia de chaves
     * - Protegida por HSM ou KMS
     * - Rotação menos frequente
     */
    MASTER_KEY("mek", "Master Encryption Key",
               "Chave mestra no topo da hierarquia",
               new int[]{256}, true, true, 365,
               new String[]{"AES_256_GCM"}),

    // === CHAVES ASSIMÉTRICAS ===
    
    /**
     * Chave para assinatura digital
     * - Par público/privado
     * - Não-repúdio
     * - Certificados digitais
     */
    DIGITAL_SIGNATURE("sig", "Digital Signature Key",
                      "Chave assimétrica para assinatura digital",
                      new int[]{2048, 3072, 4096, 256, 384}, false, true, 730,
                      new String[]{"RSA_2048", "RSA_4096", "ECDSA_P256", "ECDSA_P384", "ED25519"}),
    
    /**
     * Chave para troca de chaves
     * - Key agreement/exchange
     * - ECDH, RSA key transport
     * - Perfect Forward Secrecy
     */
    KEY_AGREEMENT("kex", "Key Exchange Key",
                  "Chave assimétrica para troca de chaves",
                  new int[]{2048, 3072, 4096, 256, 384}, false, true, 365,
                  new String[]{"RSA_2048", "ECDSA_P256", "ECDSA_P384"}),
    
    /**
     * Chave para autenticação
     * - Identidade e autenticação
     * - Certificados de cliente/servidor
     * - Mutual TLS
     */
    AUTHENTICATION("auth", "Authentication Key",
                   "Chave assimétrica para autenticação",
                   new int[]{2048, 3072, 256, 384}, false, true, 365,
                   new String[]{"RSA_2048", "ECDSA_P256", "ECDSA_P384", "ED25519"}),

    // === CHAVES ESPECIALIZADAS ===
    
    /**
     * Chave de sessão
     * - Temporária para comunicação
     * - Duração limitada
     * - Derivada ou gerada aleatoriamente
     */
    SESSION_KEY("sess", "Session Key",
                "Chave temporária para sessão de comunicação",
                new int[]{128, 256}, true, false, 1,
                new String[]{"AES_256_GCM", "CHACHA20_POLY1305"}),
    
    /**
     * Chave ephemeral (efêmera)
     * - Vida muito curta
     * - Perfect Forward Secrecy
     * - Não armazenada persistentemente
     */
    EPHEMERAL("eph", "Ephemeral Key",
              "Chave efêmera de vida muito curta",
              new int[]{256}, true, false, 0,
              new String[]{"ECDSA_P256", "ED25519"}),
    
    /**
     * Chave derivada de senha
     * - Baseada em senha do usuário
     * - Key stretching aplicado
     * - Specific para usuário
     */
    PASSWORD_DERIVED("pwd", "Password Derived Key",
                     "Chave derivada de senha do usuário",
                     new int[]{128, 256}, true, false, 90,
                     new String[]{"PBKDF2", "SCRYPT", "ARGON2ID"}),

    // === CHAVES DE INTEGRIDADE ===
    
    /**
     * Chave HMAC para integridade
     * - Message Authentication Code
     * - Verificação de integridade
     * - Anti-tampering
     */
    HMAC_KEY("hmac", "HMAC Key",
             "Chave para Message Authentication Code",
             new int[]{128, 256}, true, false, 90,
             new String[]{"HMAC_SHA256", "HMAC_SHA3_256"}),
    
    /**
     * Chave para checksum criptográfico
     * - Integridade de arquivos
     * - Verificação de dados
     * - Detecção de alterações
     */
    CHECKSUM_KEY("chk", "Checksum Key",
                 "Chave para checksum criptográfico",
                 new int[]{256}, true, false, 30,
                 new String[]{"HMAC_SHA256", "BLAKE3"}),

    // === CHAVES DE TRANSPORTE ===
    
    /**
     * Chave de transporte TLS
     * - HTTPS/TLS encryption
     * - Certificados SSL/TLS
     * - Web security
     */
    TLS_TRANSPORT("tls", "TLS Transport Key",
                  "Chave para transporte TLS/SSL",
                  new int[]{2048, 256, 384}, false, true, 365,
                  new String[]{"RSA_2048", "ECDSA_P256", "ECDSA_P384"}),
    
    /**
     * Chave para VPN
     * - Virtual Private Network
     * - Túneis seguros
     * - Site-to-site encryption
     */
    VPN_TUNNEL("vpn", "VPN Tunnel Key",
               "Chave para túneis VPN",
               new int[]{256}, true, false, 30,
               new String[]{"AES_256_GCM", "CHACHA20_POLY1305"}),

    // === CHAVES DE BACKUP ===
    
    /**
     * Chave de backup/escrow
     * - Recovery purposes
     * - Disaster recovery
     * - Legal compliance
     */
    BACKUP_ESCROW("bkp", "Backup/Escrow Key",
                  "Chave para backup e recuperação",
                  new int[]{256}, true, true, 1095,
                  new String[]{"AES_256_GCM"}),
    
    /**
     * Chave de teste
     * - Ambiente de desenvolvimento/teste
     * - Não deve ser usada em produção
     * - Rotação relaxada
     */
    TEST_KEY("test", "Test Key",
             "Chave para ambiente de teste",
             new int[]{128, 256}, true, false, 7,
             new String[]{"AES_128_GCM", "AES_256_GCM"});

    private final String codigo;
    private final String nome;
    private final String descricao;
    private final int[] tamanhosSuportados;
    private final boolean simetrica;
    private final boolean requerHSM;
    private final int diasRotacao;
    private final String[] algoritmosCompativeis;

    TipoChave(String codigo, String nome, String descricao, 
              int[] tamanhosSuportados, boolean simetrica, boolean requerHSM,
              int diasRotacao, String[] algoritmosCompativeis) {
        this.codigo = codigo;
        this.nome = nome;
        this.descricao = descricao;
        this.tamanhosSuportados = tamanhosSuportados;
        this.simetrica = simetrica;
        this.requerHSM = requerHSM;
        this.diasRotacao = diasRotacao;
        this.algoritmosCompativeis = algoritmosCompativeis;
    }

    // === MÉTODOS DE CLASSIFICAÇÃO ===

    /**
     * Verifica se é chave simétrica
     */
    public boolean isSimetrica() {
        return simetrica;
    }

    /**
     * Verifica se é chave assimétrica
     */
    public boolean isAssimetrica() {
        return !simetrica;
    }

    /**
     * Verifica se requer HSM para proteção
     */
    public boolean requerHSM() {
        return requerHSM;
    }

    /**
     * Verifica se é chave temporária (vida curta)
     */
    public boolean isTemporaria() {
        return this == SESSION_KEY || this == EPHEMERAL || diasRotacao <= 1;
    }

    /**
     * Verifica se é chave de alta segurança
     */
    public boolean isAltaSeguranca() {
        return this == MASTER_KEY || this == KEY_ENCRYPTION || 
               this == DIGITAL_SIGNATURE || requerHSM;
    }

    /**
     * Verifica se pode ser exportada
     */
    public boolean podeSerExportada() {
        return this != MASTER_KEY && this != KEY_ENCRYPTION && !requerHSM;
    }

    /**
     * Verifica se é chave de dados (end-user data)
     */
    public boolean isChaveDados() {
        return this == DATA_ENCRYPTION || this == SESSION_KEY || this == VPN_TUNNEL;
    }

    /**
     * Verifica se é chave de infraestrutura
     */
    public boolean isChaveInfraestrutura() {
        return this == MASTER_KEY || this == KEY_ENCRYPTION || 
               this == TLS_TRANSPORT || this == AUTHENTICATION;
    }

    // === CONFIGURAÇÕES ESPECÍFICAS ===

    /**
     * Obtém tamanho de chave recomendado
     */
    public int getTamanhoRecomendado() {
        // Retorna o maior tamanho suportado (mais seguro)
        int max = 0;
        for (int tamanho : tamanhosSuportados) {
            if (tamanho > max) max = tamanho;
        }
        return max;
    }

    /**
     * Obtém tamanho mínimo de chave
     */
    public int getTamanhoMinimo() {
        int min = Integer.MAX_VALUE;
        for (int tamanho : tamanhosSuportados) {
            if (tamanho < min) min = tamanho;
        }
        return min == Integer.MAX_VALUE ? 128 : min;
    }

    /**
     * Verifica se suporta tamanho específico
     */
    public boolean suportaTamanho(int tamanho) {
        for (int t : tamanhosSuportados) {
            if (t == tamanho) return true;
        }
        return false;
    }

    /**
     * Obtém algoritmo recomendado para este tipo
     */
    public String getAlgoritmoRecomendado() {
        if (algoritmosCompativeis.length > 0) {
            return algoritmosCompativeis[0]; // Primeiro é o recomendado
        }
        return null;
    }

    /**
     * Verifica se é compatível com algoritmo
     */
    public boolean isCompativelCom(String algoritmo) {
        for (String alg : algoritmosCompativeis) {
            if (alg.equals(algoritmo)) return true;
        }
        return false;
    }

    /**
     * Obtém nível de proteção necessário
     */
    public NivelProtecao getNivelProtecao() {
        return switch (this) {
            case MASTER_KEY -> NivelProtecao.CRITICO;
            case KEY_ENCRYPTION, DIGITAL_SIGNATURE -> NivelProtecao.ALTO;
            case AUTHENTICATION, TLS_TRANSPORT, BACKUP_ESCROW -> NivelProtecao.MEDIO;
            case DATA_ENCRYPTION, HMAC_KEY -> NivelProtecao.NORMAL;
            case SESSION_KEY, EPHEMERAL, TEST_KEY -> NivelProtecao.BAIXO;
            default -> NivelProtecao.NORMAL;
        };
    }

    /**
     * Obtém frequência de rotação em dias
     */
    public int getFrequenciaRotacaoDias() {
        return diasRotacao;
    }

    /**
     * Verifica se precisa de rotação baseada na data
     */
    public boolean precisaRotacao(java.time.LocalDateTime criadaEm) {
        if (diasRotacao == 0) return false; // Chaves efêmeras não rotacionam
        
        java.time.LocalDateTime agora = java.time.LocalDateTime.now();
        long diasDesdecriacao = java.time.temporal.ChronoUnit.DAYS.between(criadaEm, agora);
        
        return diasDesdeCreacao >= diasRotacao;
    }

    // === MÉTODOS DE BUSCA ===

    /**
     * Busca tipo por código
     */
    public static TipoChave porCodigo(String codigo) {
        for (TipoChave tipo : values()) {
            if (tipo.codigo.equalsIgnoreCase(codigo)) {
                return tipo;
            }
        }
        throw new IllegalArgumentException("Tipo de chave não encontrado: " + codigo);
    }

    /**
     * Obtém todos os tipos simétricos
     */
    public static TipoChave[] getTiposSimetricos() {
        return java.util.Arrays.stream(values())
            .filter(TipoChave::isSimetrica)
            .toArray(TipoChave[]::new);
    }

    /**
     * Obtém todos os tipos assimétricos
     */
    public static TipoChave[] getTiposAssimetricos() {
        return java.util.Arrays.stream(values())
            .filter(TipoChave::isAssimetrica)
            .toArray(TipoChave[]::new);
    }

    /**
     * Obtém tipos que requerem HSM
     */
    public static TipoChave[] getTiposHSM() {
        return java.util.Arrays.stream(values())
            .filter(TipoChave::requerHSM)
            .toArray(TipoChave[]::new);
    }

    /**
     * Obtém tipos por nível de proteção
     */
    public static TipoChave[] getTiposPorProtecao(NivelProtecao nivel) {
        return java.util.Arrays.stream(values())
            .filter(tipo -> tipo.getNivelProtecao() == nivel)
            .toArray(TipoChave[]::new);
    }

    // === VALIDAÇÕES ===

    /**
     * Valida configuração da chave
     */
    public void validarConfiguracao(int tamanho, String algoritmo) {
        if (!suportaTamanho(tamanho)) {
            throw new IllegalArgumentException(String.format(
                "Tamanho %d não suportado para tipo %s. Tamanhos válidos: %s",
                tamanho, this, java.util.Arrays.toString(tamanhosSuportados)
            ));
        }
        
        if (algoritmo != null && !isCompativelCom(algoritmo)) {
            throw new IllegalArgumentException(String.format(
                "Algoritmo %s não compatível com tipo %s. Algoritmos válidos: %s",
                algoritmo, this, java.util.Arrays.toString(algoritmosCompativeis)
            ));
        }
    }

    // === GETTERS ===

    public String getCodigo() {
        return codigo;
    }

    public String getNome() {
        return nome;
    }

    public String getDescricao() {
        return descricao;
    }

    public int[] getTamanhosSuportados() {
        return tamanhosSuportados.clone();
    }

    public String[] getAlgoritmosCompativeis() {
        return algoritmosCompativeis.clone();
    }

    @Override
    public String toString() {
        return String.format("%s (%s)", nome, codigo);
    }

    // === ENUM AUXILIAR ===

    public enum NivelProtecao {
        BAIXO("Baixo", 1, "Proteção básica"),
        NORMAL("Normal", 2, "Proteção padrão"),
        MEDIO("Médio", 3, "Proteção elevada"),
        ALTO("Alto", 4, "Proteção alta"),
        CRITICO("Crítico", 5, "Proteção máxima");

        private final String nome;
        private final int nivel;
        private final String descricao;

        NivelProtecao(String nome, int nivel, String descricao) {
            this.nome = nome;
            this.nivel = nivel;
            this.descricao = descricao;
        }

        public String getNome() { return nome; }
        public int getNivel() { return nivel; }
        public String getDescricao() { return descricao; }
        
        public boolean isMaiorQue(NivelProtecao outro) {
            return this.nivel > outro.nivel;
        }
    }
}