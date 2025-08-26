package br.tec.facilitaservicos.criptografia.dominio.enums;

import java.time.LocalDateTime;
import java.time.Duration;

/**
 * ============================================================================
 * 🔑 STATUS DE CHAVES CRIPTOGRÁFICAS
 * ============================================================================
 * 
 * Enum que define os diferentes estados de uma chave criptográfica:
 * - Estados do ciclo de vida (criada, ativa, rotação, revogada)
 * - Estados operacionais (habilitada, desabilitada, suspensa)
 * - Estados de segurança (comprometida, expirada, backup)
 * 
 * Cada status tem comportamentos específicos:
 * - Se pode ser usada para criptografia
 * - Se pode ser usada para descriptografia
 * - Se pode ser exportada
 * - Ações automáticas permitidas
 * 
 * @author Sistema de Migração R2DBC
 * @version 1.0
 * @since 2024
 */
public enum StatusChave {

    // === ESTADOS DO CICLO DE VIDA ===
    
    /**
     * Chave criada mas ainda não ativa
     */
    CRIADA(0, "Criada", "Chave criada mas ainda não ativada", 
           false, true, false, false, true),
    
    /**
     * Chave ativa e pronta para uso
     */
    ATIVA(1, "Ativa", "Chave ativa e operacional", 
          true, true, false, true, true),
    
    /**
     * Chave em processo de rotação
     */
    ROTACAO(2, "Em Rotação", "Chave sendo substituída por nova versão", 
            false, true, false, false, true),
    
    /**
     * Chave foi substituída por nova versão
     */
    SUBSTITUIDA(3, "Substituída", "Chave foi substituída por versão mais nova", 
                false, true, false, false, false),

    // === ESTADOS OPERACIONAIS ===
    
    /**
     * Chave temporariamente desabilitada
     */
    DESABILITADA(10, "Desabilitada", "Chave temporariamente desabilitada", 
                 false, true, false, false, false),
    
    /**
     * Chave suspensa por motivos de segurança
     */
    SUSPENSA(11, "Suspensa", "Chave suspensa por questões de segurança", 
             false, true, false, false, false),
    
    /**
     * Chave pausada para manutenção
     */
    PAUSADA(12, "Pausada", "Chave pausada para manutenção", 
            false, true, false, false, false),

    // === ESTADOS DE SEGURANÇA ===
    
    /**
     * Chave comprometida - não deve mais ser usada
     */
    COMPROMETIDA(20, "Comprometida", "Chave possivelmente comprometida", 
                 false, true, true, false, false),
    
    /**
     * Chave expirada por tempo
     */
    EXPIRADA(21, "Expirada", "Chave expirou por limite de tempo", 
             false, true, false, false, false),
    
    /**
     * Chave revogada permanentemente
     */
    REVOGADA(22, "Revogada", "Chave revogada permanentemente", 
             false, false, true, false, false),
    
    /**
     * Chave destruída/removida
     */
    DESTRUIDA(23, "Destruída", "Chave foi destruída de forma segura", 
              false, false, true, false, false),

    // === ESTADOS ESPECIAIS ===
    
    /**
     * Chave em backup/arquivada
     */
    BACKUP(30, "Backup", "Chave arquivada como backup", 
           false, true, false, false, false),
    
    /**
     * Chave sendo importada
     */
    IMPORTANDO(31, "Importando", "Chave sendo importada de fonte externa", 
               false, false, false, false, false),
    
    /**
     * Chave sendo exportada
     */
    EXPORTANDO(32, "Exportando", "Chave sendo exportada", 
               false, true, false, false, false),
    
    /**
     * Chave em processo de escrow
     */
    ESCROW(33, "Escrow", "Chave depositada em escrow", 
           false, true, false, false, false);

    private final int codigo;
    private final String nome;
    private final String descricao;
    private final boolean podeEncriptar;
    private final boolean podeDescriptar;
    private final boolean comprometida;
    private final boolean podeExportar;
    private final boolean podeRotacionar;

    StatusChave(int codigo, String nome, String descricao, 
                boolean podeEncriptar, boolean podeDescriptar, 
                boolean comprometida, boolean podeExportar, boolean podeRotacionar) {
        this.codigo = codigo;
        this.nome = nome;
        this.descricao = descricao;
        this.podeEncriptar = podeEncriptar;
        this.podeDescriptar = podeDescriptar;
        this.comprometida = comprometida;
        this.podeExportar = podeExportar;
        this.podeRotacionar = podeRotacionar;
    }

    // === MÉTODOS DE CLASSIFICAÇÃO ===

    /**
     * Verifica se é um estado inicial (antes de ativar)
     */
    public boolean isInicial() {
        return this == CRIADA || this == IMPORTANDO;
    }

    /**
     * Verifica se é um estado ativo (operacional)
     */
    public boolean isAtiva() {
        return this == ATIVA;
    }

    /**
     * Verifica se é um estado de transição
     */
    public boolean isTransicao() {
        return this == ROTACAO || this == IMPORTANDO || this == EXPORTANDO;
    }

    /**
     * Verifica se é um estado temporário
     */
    public boolean isTemporario() {
        return this == DESABILITADA || this == SUSPENSA || this == PAUSADA;
    }

    /**
     * Verifica se é um estado permanente
     */
    public boolean isPermanente() {
        return this == REVOGADA || this == DESTRUIDA || this == SUBSTITUIDA;
    }

    /**
     * Verifica se é um estado de segurança
     */
    public boolean isSeguranca() {
        return comprometida || this == REVOGADA || this == DESTRUIDA;
    }

    /**
     * Verifica se a chave pode ser reativada
     */
    public boolean podeReativar() {
        return this == DESABILITADA || this == PAUSADA || this == SUSPENSA;
    }

    /**
     * Verifica se a chave pode ser editada
     */
    public boolean podeEditar() {
        return !isPermanente() && !isTransicao();
    }

    /**
     * Verifica se a chave pode ser removida
     */
    public boolean podeRemover() {
        return this != ATIVA && !isTransicao();
    }

    // === TRANSIÇÕES DE ESTADO ===

    /**
     * Obtém os próximos estados possíveis a partir deste estado
     */
    public StatusChave[] getProximosEstadosPossiveis() {
        return switch (this) {
            case CRIADA -> new StatusChave[]{ATIVA, DESABILITADA, REVOGADA, DESTRUIDA};
            case ATIVA -> new StatusChave[]{ROTACAO, DESABILITADA, SUSPENSA, PAUSADA, COMPROMETIDA, EXPIRADA, REVOGADA};
            case ROTACAO -> new StatusChave[]{SUBSTITUIDA, ATIVA, COMPROMETIDA};
            case SUBSTITUIDA -> new StatusChave[]{BACKUP, DESTRUIDA};
            case DESABILITADA -> new StatusChave[]{ATIVA, SUSPENSA, REVOGADA, DESTRUIDA};
            case SUSPENSA -> new StatusChave[]{ATIVA, DESABILITADA, COMPROMETIDA, REVOGADA};
            case PAUSADA -> new StatusChave[]{ATIVA, DESABILITADA, REVOGADA};
            case COMPROMETIDA -> new StatusChave[]{REVOGADA, DESTRUIDA};
            case EXPIRADA -> new StatusChave[]{ROTACAO, BACKUP, DESTRUIDA};
            case BACKUP -> new StatusChave[]{ATIVA, DESTRUIDA};
            case IMPORTANDO -> new StatusChave[]{CRIADA, ATIVA, REVOGADA};
            case EXPORTANDO -> new StatusChave[]{ATIVA, DESABILITADA};
            case ESCROW -> new StatusChave[]{ATIVA, BACKUP, DESTRUIDA};
            default -> new StatusChave[]{};
        };
    }

    /**
     * Verifica se pode transicionar para outro status
     */
    public boolean podeTransicionarPara(StatusChave novoStatus) {
        StatusChave[] possiveis = getProximosEstadosPossiveis();
        for (StatusChave status : possiveis) {
            if (status == novoStatus) {
                return true;
            }
        }
        return false;
    }

    // === CONFIGURAÇÕES POR STATUS ===

    /**
     * Obtém o tempo máximo recomendado neste status (em horas)
     */
    public Duration getTempoMaximoRecomendado() {
        return switch (this) {
            case CRIADA -> Duration.ofHours(24); // 1 dia para ativar
            case ROTACAO -> Duration.ofMinutes(30); // 30 minutos para rotacionar
            case PAUSADA -> Duration.ofHours(4); // 4 horas pausada
            case SUSPENSA -> Duration.ofDays(7); // 1 semana suspensa
            case IMPORTANDO, EXPORTANDO -> Duration.ofMinutes(15); // 15 minutos para operação
            case COMPROMETIDA -> Duration.ofHours(1); // 1 hora para revogar
            default -> Duration.ofDays(365); // 1 ano padrão
        };
    }

    /**
     * Verifica se deve notificar sobre mudança de status
     */
    public boolean deveNotificar() {
        return this == COMPROMETIDA || this == REVOGADA || this == EXPIRADA || 
               this == DESTRUIDA || this == SUSPENSA;
    }

    /**
     * Obtém o nível de alerta
     */
    public NivelAlerta getNivelAlerta() {
        return switch (this) {
            case COMPROMETIDA, REVOGADA -> NivelAlerta.CRITICO;
            case SUSPENSA, EXPIRADA -> NivelAlerta.ALTO;
            case DESABILITADA, PAUSADA -> NivelAlerta.MEDIO;
            case ROTACAO, SUBSTITUIDA -> NivelAlerta.BAIXO;
            default -> NivelAlerta.INFORMATIVO;
        };
    }

    /**
     * Obtém cor para exibição em interfaces
     */
    public String getCor() {
        return switch (this) {
            case ATIVA -> "#28a745"; // Verde
            case CRIADA -> "#17a2b8"; // Azul
            case ROTACAO, IMPORTANDO, EXPORTANDO -> "#ffc107"; // Amarelo
            case DESABILITADA, PAUSADA -> "#6c757d"; // Cinza
            case SUSPENSA -> "#fd7e14"; // Laranja
            case COMPROMETIDA, REVOGADA -> "#dc3545"; // Vermelho
            case EXPIRADA -> "#e83e8c"; // Rosa
            case DESTRUIDA -> "#495057"; // Cinza escuro
            case BACKUP, ESCROW -> "#20c997"; // Verde água
            default -> "#6f42c1"; // Roxo
        };
    }

    // === MÉTRICAS E AUDITORIA ===

    /**
     * Verifica se deve ser incluído em estatísticas de uso
     */
    public boolean incluirNasEstatisticas() {
        return this == ATIVA || this == ROTACAO;
    }

    /**
     * Verifica se deve ser auditado
     */
    public boolean deveAuditar() {
        return this != CRIADA && this != BACKUP;
    }

    /**
     * Obtém peso para cálculo de métricas (0-100)
     */
    public int getPesoMetricas() {
        return switch (this) {
            case ATIVA -> 100;
            case ROTACAO -> 80;
            case CRIADA -> 50;
            case SUBSTITUIDA -> 30;
            case DESABILITADA, PAUSADA -> 20;
            case BACKUP -> 10;
            default -> 0;
        };
    }

    // === MÉTODOS UTILITÁRIOS ===

    /**
     * Busca status por código numérico
     */
    public static StatusChave porCodigo(int codigo) {
        for (StatusChave status : values()) {
            if (status.codigo == codigo) {
                return status;
            }
        }
        return CRIADA; // Fallback
    }

    /**
     * Busca status por nome
     */
    public static StatusChave porNome(String nome) {
        if (nome == null || nome.trim().isEmpty()) {
            return CRIADA;
        }
        
        try {
            return valueOf(nome.toUpperCase().replace(" ", "_"));
        } catch (IllegalArgumentException e) {
            // Tentar nomes alternativos
            String upper = nome.toUpperCase();
            return switch (upper) {
                case "ACTIVE", "ENABLED" -> ATIVA;
                case "DISABLED", "INACTIVE" -> DESABILITADA;
                case "SUSPENDED" -> SUSPENSA;
                case "COMPROMISED" -> COMPROMETIDA;
                case "EXPIRED" -> EXPIRADA;
                case "REVOKED" -> REVOGADA;
                case "DESTROYED", "DELETED" -> DESTRUIDA;
                default -> CRIADA;
            };
        }
    }

    /**
     * Obtém emoji representativo do status
     */
    public String getEmoji() {
        return switch (this) {
            case CRIADA -> "🆕";
            case ATIVA -> "✅";
            case ROTACAO -> "🔄";
            case SUBSTITUIDA -> "🔀";
            case DESABILITADA -> "❌";
            case SUSPENSA -> "⏸️";
            case PAUSADA -> "⏯️";
            case COMPROMETIDA -> "🚨";
            case EXPIRADA -> "⏰";
            case REVOGADA -> "🚫";
            case DESTRUIDA -> "💥";
            case BACKUP -> "💾";
            case IMPORTANDO -> "📥";
            case EXPORTANDO -> "📤";
            case ESCROW -> "🏛️";
            default -> "❓";
        };
    }

    /**
     * Obtém todos os status operacionais
     */
    public static StatusChave[] getStatusOperacionais() {
        return new StatusChave[]{ATIVA, ROTACAO, DESABILITADA, SUSPENSA, PAUSADA};
    }

    /**
     * Obtém todos os status de segurança
     */
    public static StatusChave[] getStatusSeguranca() {
        return new StatusChave[]{COMPROMETIDA, REVOGADA, DESTRUIDA};
    }

    /**
     * Obtém todos os status que permitem criptografia
     */
    public static StatusChave[] getStatusEncriptacao() {
        return java.util.Arrays.stream(values())
            .filter(status -> status.podeEncriptar)
            .toArray(StatusChave[]::new);
    }

    // === GETTERS ===

    public int getCodigo() {
        return codigo;
    }

    public String getNome() {
        return nome;
    }

    public String getDescricao() {
        return descricao;
    }

    public boolean isPodeEncriptar() {
        return podeEncriptar;
    }

    public boolean isPodeDescriptar() {
        return podeDescriptar;
    }

    public boolean isComprometida() {
        return comprometida;
    }

    public boolean isPodeExportar() {
        return podeExportar;
    }

    public boolean isPodeRotacionar() {
        return podeRotacionar;
    }

    @Override
    public String toString() {
        return String.format("%s %s (%d)", getEmoji(), nome, codigo);
    }

    // === ENUM AUXILIAR ===

    public enum NivelAlerta {
        INFORMATIVO("Informativo", "#17a2b8"),
        BAIXO("Baixo", "#28a745"),
        MEDIO("Médio", "#ffc107"),
        ALTO("Alto", "#fd7e14"),
        CRITICO("Crítico", "#dc3545");

        private final String nome;
        private final String cor;

        NivelAlerta(String nome, String cor) {
            this.nome = nome;
            this.cor = cor;
        }

        public String getNome() { return nome; }
        public String getCor() { return cor; }
    }
}