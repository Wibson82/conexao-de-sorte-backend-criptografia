package br.tec.facilitaservicos.criptografia.dominio.entidade;

import br.tec.facilitaservicos.criptografia.dominio.enums.AlgoritmosCriptograficos;
import br.tec.facilitaservicos.criptografia.dominio.enums.StatusChave;
import br.tec.facilitaservicos.criptografia.dominio.enums.TipoChave;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.*;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

/**
 * ============================================================================
 * 🔑 ENTIDADE CHAVE CRIPTOGRÁFICA R2DBC
 * ============================================================================
 * 
 * Entidade principal para gerenciamento de chaves criptográficas com R2DBC.
 * 
 * 🛡️ RECURSOS DE SEGURANÇA:
 * - Zero-knowledge storage (chave nunca exposta)
 * - Metadata criptografada
 * - Audit trail completo
 * - Versionamento de chaves
 * - Rotação automática
 * - HSM integration ready
 * 
 * 🔐 GESTÃO DE CICLO DE VIDA:
 * - Estados de chave (ativa, revogada, expirada)
 * - Transições controladas
 * - Políticas de retenção
 * - Backup e recuperação
 * - Compliance tracking
 * 
 * 📊 MONITORAMENTO:
 * - Métricas de uso
 * - Performance tracking
 * - Anomaly detection
 * - Security events
 * 
 * @author Sistema de Migração R2DBC
 * @version 1.0
 * @since 2024
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("chaves")
public class ChaveR2dbc {

    @Id
    @Column("id")
    private String id;

    @Column("nome")
    private String nome;

    @Column("descricao")
    private String descricao;

    @Column("tipo")
    private TipoChave tipo;

    @Column("algoritmo")
    private AlgoritmosCriptograficos algoritmo;

    @Column("status")
    private StatusChave status;

    @Column("tamanho_bits")
    private Integer tamanhoBits;

    @Column("versao")
    private Integer versao;

    @Column("chave_pai_id")
    private String chavePaiId;

    @Column("tenant_id")
    private String tenantId;

    @Column("aplicacao")
    private String aplicacao;

    @Column("ambiente")
    private String ambiente;

    // === DADOS CRIPTOGRÁFICOS (NUNCA EXPOSTOS) ===

    @Column("key_id_externo")
    private String keyIdExterno; // ID no HSM/KMS externo

    @Column("fingerprint")
    private String fingerprint; // Hash da chave para identificação

    @Column("checksum")
    private String checksum; // Verificação de integridade

    // === CONFIGURAÇÕES DE SEGURANÇA ===

    @Column("nivel_protecao")
    private String nivelProtecao; // BAIXO, NORMAL, ALTO, CRITICO

    @Column("requer_hsm")
    private Boolean requerHSM;

    @Column("criptografada_por_kek")
    private Boolean criptografadaPorKEK;

    @Column("kek_id")
    private String kekId; // ID da Key Encryption Key

    @Column("exportavel")
    private Boolean exportavel;

    @Column("backup_permitido")
    private Boolean backupPermitido;

    // === POLÍTICAS E COMPLIANCE ===

    @Column("classificacao_dados")
    private String classificacaoDados; // PUBLICO, INTERNO, CONFIDENCIAL, RESTRITO

    @Column("pais_origem")
    private String paisOrigemDataSoberania;

    @Column("regulamentacoes")
    private String regulamentacoes; // LGPD, GDPR, HIPAA, PCI-DSS

    @Column("politica_retencao_dias")
    private Integer politicaRetencaoDias;

    @Column("politica_rotacao_dias")
    private Integer politicaRotacaoDias;

    // === CONTROLE DE USO ===

    @Column("permitir_encriptacao")
    private Boolean permitirEncriptacao;

    @Column("permitir_descriptacao")
    private Boolean permitirDescriptacao;

    @Column("permitir_assinatura")
    private Boolean permitirAssinatura;

    @Column("permitir_verificacao")
    private Boolean permitirVerificacao;

    @Column("usos_maximos")
    private Long usosMaximos;

    @Column("usos_atuais")
    private Long usosAtuais;

    // === MÉTRICAS E AUDITORIA ===

    @Column("total_operacoes")
    private Long totalOperacoes;

    @Column("total_bytes_processados")
    private Long totalBytesProcessados;

    @Column("ultima_utilizacao")
    private LocalDateTime ultimaUtilizacao;

    @Column("ultimo_acesso_usuario")
    private String ultimoAcessoUsuario;

    @Column("ultimo_acesso_aplicacao")
    private String ultimoAcessoAplicacao;

    @Column("contador_falhas")
    private Integer contadorFalhas;

    @Column("alertas_seguranca")
    private Integer alertasSeguranca;

    // === CONFIGURAÇÕES ALGORÍTMICAS ===

    @Column("parametros_algoritmo")
    private String parametrosAlgoritmo; // JSON com parâmetros específicos

    @Column("curva_eliptica")
    private String curvaEliptica; // Para ECDSA/ECDH

    @Column("padding_scheme")
    private String paddingScheme; // Para RSA

    @Column("modo_operacao")
    private String modoOperacao; // GCM, CTR, etc.

    @Column("tamanho_tag_autenticacao")
    private Integer tamanhoTagAutenticacao;

    // === DATAS E VERSIONAMENTO ===

    @Column("valida_a_partir_de")
    private LocalDateTime validaAPartirDe;

    @Column("valida_ate")
    private LocalDateTime validaAte;

    @Column("ultima_rotacao")
    private LocalDateTime ultimaRotacao;

    @Column("proxima_rotacao")
    private LocalDateTime proximaRotacao;

    @Column("status_anterior")
    private StatusChave statusAnterior;

    @Column("motivo_mudanca_status")
    private String motivoMudancaStatus;

    // === METADADOS ADICIONAIS ===

    @Column("metadados")
    private String metadados; // JSON com dados extras

    @Column("tags")
    private String tags; // Tags para organização

    @Column("proprietario")
    private String proprietario;

    @Column("grupo_acesso")
    private String grupoAcesso;

    @Column("observacoes")
    private String observacoes;

    // === AUDITORIA PADRÃO ===

    @Column("ativo")
    private Boolean ativo;

    @CreatedDate
    @Column("criado_em")
    private LocalDateTime criadoEm;

    @CreatedBy
    @Column("criado_por")
    private String criadoPor;

    @LastModifiedDate
    @Column("atualizado_em")
    private LocalDateTime atualizadoEm;

    @LastModifiedBy
    @Column("atualizado_por")
    private String atualizadoPor;

    // === CONSTRUTORES E INICIALIZAÇÃO ===

    @Builder
    public ChaveR2dbc(String nome, String descricao, TipoChave tipo, 
                      AlgoritmosCriptograficos algoritmo, Integer tamanhoBits,
                      String tenantId, String aplicacao, String ambiente) {
        this.id = UUID.randomUUID().toString();
        this.nome = nome;
        this.descricao = descricao;
        this.tipo = tipo;
        this.algoritmo = algoritmo;
        this.tamanhoBits = tamanhoBits;
        this.tenantId = tenantId;
        this.aplicacao = aplicacao;
        this.ambiente = ambiente;
        
        // Valores padrão baseados no tipo
        this.status = StatusChave.CRIADA;
        this.versao = 1;
        this.nivelProtecao = tipo.getNivelProtecao().name();
        this.requerHSM = tipo.requerHSM();
        this.exportavel = tipo.podeSerExportada();
        this.backupPermitido = !tipo.requerHSM();
        this.politicaRotacaoDias = tipo.getFrequenciaRotacaoDias();
        this.permitirEncriptacao = tipo.isSimetrica() || tipo == TipoChave.AUTHENTICATION;
        this.permitirDescriptacao = tipo.isSimetrica();
        this.permitirAssinatura = tipo.isAssimetrica();
        this.permitirVerificacao = tipo.isAssimetrica();
        this.usosAtuais = 0L;
        this.totalOperacoes = 0L;
        this.totalBytesProcessados = 0L;
        this.contadorFalhas = 0;
        this.alertasSeguranca = 0;
        this.ativo = true;
        this.validaAPartirDe = LocalDateTime.now();
        
        // Configurar validade baseada no tipo
        if (tipo.getFrequenciaRotacaoDias() > 0) {
            this.validaAte = LocalDateTime.now().plusDays(tipo.getFrequenciaRotacaoDias());
            this.proximaRotacao = this.validaAte.minusDays(7); // Alert 7 dias antes
        }
    }

    // === MÉTODOS DE NEGÓCIO ===

    /**
     * Verifica se a chave está expirada
     */
    public boolean isExpirada() {
        return validaAte != null && validaAte.isBefore(LocalDateTime.now());
    }

    /**
     * Verifica se a chave precisa de rotação
     */
    public boolean precisaRotacao() {
        return proximaRotacao != null && proximaRotacao.isBefore(LocalDateTime.now());
    }

    /**
     * Verifica se a chave pode ser usada para operação específica
     */
    public boolean podeSerUsadaPara(TipoOperacao operacao) {
        if (!status.isPodeEncriptar() && !status.isPodeDescriptar()) {
            return false;
        }
        
        if (isExpirada()) {
            return false;
        }
        
        return switch (operacao) {
            case ENCRIPTACAO -> permitirEncriptacao && status.isPodeEncriptar();
            case DESCRIPTACAO -> permitirDescriptacao && status.isPodeDescriptar();
            case ASSINATURA -> permitirAssinatura && status.isPodeEncriptar();
            case VERIFICACAO -> permitirVerificacao && status.isPodeDescriptar();
        };
    }

    /**
     * Registra uso da chave
     */
    public void registrarUso(TipoOperacao operacao, long bytesProcessados, String usuario, String aplicacao) {
        this.usosAtuais = (this.usosAtuais != null ? this.usosAtuais : 0L) + 1;
        this.totalOperacoes = (this.totalOperacoes != null ? this.totalOperacoes : 0L) + 1;
        this.totalBytesProcessados = (this.totalBytesProcessados != null ? this.totalBytesProcessados : 0L) + bytesProcessados;
        this.ultimaUtilizacao = LocalDateTime.now();
        this.ultimoAcessoUsuario = usuario;
        this.ultimoAcessoAplicacao = aplicacao;
        
        // Verificar se excedeu uso máximo
        if (usosMaximos != null && usosAtuais >= usosMaximos) {
            this.status = StatusChave.EXPIRADA;
            this.motivoMudancaStatus = "Limite de usos atingido";
        }
    }

    /**
     * Registra falha na operação
     */
    public void registrarFalha(String motivo) {
        this.contadorFalhas = (this.contadorFalhas != null ? this.contadorFalhas : 0) + 1;
        
        // Se muitas falhas, suspender chave
        if (this.contadorFalhas >= 10) {
            this.statusAnterior = this.status;
            this.status = StatusChave.SUSPENSA;
            this.motivoMudancaStatus = "Muitas falhas de operação: " + motivo;
        }
    }

    /**
     * Inicia rotação da chave
     */
    public void iniciarRotacao() {
        if (!status.isPodeRotacionar()) {
            throw new IllegalStateException("Chave não pode ser rotacionada no status: " + status);
        }
        
        this.statusAnterior = this.status;
        this.status = StatusChave.ROTACAO;
        this.motivoMudancaStatus = "Rotação iniciada";
        this.ultimaRotacao = LocalDateTime.now();
    }

    /**
     * Completa rotação da chave
     */
    public void completarRotacao() {
        if (this.status != StatusChave.ROTACAO) {
            throw new IllegalStateException("Chave não está em rotação");
        }
        
        this.status = StatusChave.SUBSTITUIDA;
        this.motivoMudancaStatus = "Rotação completada";
        
        // Recalcular próxima rotação se aplicável
        if (politicaRotacaoDias != null && politicaRotacaoDias > 0) {
            this.proximaRotacao = LocalDateTime.now().plusDays(politicaRotacaoDias - 7);
        }
    }

    /**
     * Revoga a chave permanentemente
     */
    public void revogar(String motivo) {
        this.statusAnterior = this.status;
        this.status = StatusChave.REVOGADA;
        this.motivoMudancaStatus = motivo;
        this.ativo = false;
    }

    /**
     * Marca chave como comprometida
     */
    public void marcarComprometida(String motivo) {
        this.statusAnterior = this.status;
        this.status = StatusChave.COMPROMETIDA;
        this.motivoMudancaStatus = motivo;
        this.alertasSeguranca = (this.alertasSeguranca != null ? this.alertasSeguranca : 0) + 1;
    }

    /**
     * Ativa a chave se possível
     */
    public void ativar() {
        if (!status.podeTransicionarPara(StatusChave.ATIVA)) {
            throw new IllegalStateException("Não é possível ativar chave no status: " + status);
        }
        
        this.statusAnterior = this.status;
        this.status = StatusChave.ATIVA;
        this.motivoMudancaStatus = "Chave ativada";
    }

    /**
     * Obtém idade da chave em dias
     */
    public long getIdadeDias() {
        if (criadoEm == null) return 0;
        return java.time.temporal.ChronoUnit.DAYS.between(criadoEm, LocalDateTime.now());
    }

    /**
     * Obtém dias restantes até expiração
     */
    public long getDiasAteExpiracao() {
        if (validaAte == null) return Long.MAX_VALUE;
        return java.time.temporal.ChronoUnit.DAYS.between(LocalDateTime.now(), validaAte);
    }

    /**
     * Verifica se a chave está próxima da expiração
     */
    public boolean isProximaDaExpiracao(int diasAntecedencia) {
        return getDiasAteExpiracao() <= diasAntecedencia;
    }

    /**
     * Obtém taxa de uso (usos/dia)
     */
    public double getTaxaUso() {
        long idadeDias = getIdadeDias();
        if (idadeDias == 0) idadeDias = 1; // Evitar divisão por zero
        return (totalOperacoes != null ? totalOperacoes : 0L) / (double) idadeDias;
    }

    /**
     * Converte metadados JSON para Map
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getMetadadosMap() {
        if (metadados == null || metadados.trim().isEmpty()) {
            return Map.of();
        }
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().readValue(metadados, Map.class);
        } catch (Exception e) {
            return Map.of();
        }
    }

    /**
     * Define metadados a partir de Map
     */
    public void setMetadadosMap(Map<String, Object> metadadosMap) {
        if (metadadosMap == null || metadadosMap.isEmpty()) {
            this.metadados = null;
            return;
        }
        try {
            this.metadados = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(metadadosMap);
        } catch (Exception e) {
            this.metadados = null;
        }
    }

    // === ENUM AUXILIAR ===

    public enum TipoOperacao {
        ENCRIPTACAO("Encriptação"),
        DESCRIPTACAO("Descriptação"),
        ASSINATURA("Assinatura Digital"),
        VERIFICACAO("Verificação de Assinatura");

        private final String descricao;

        TipoOperacao(String descricao) {
            this.descricao = descricao;
        }

        public String getDescricao() {
            return descricao;
        }
    }
}