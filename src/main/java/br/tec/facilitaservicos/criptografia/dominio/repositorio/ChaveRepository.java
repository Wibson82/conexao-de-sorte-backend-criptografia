package br.tec.facilitaservicos.criptografia.dominio.repositorio;

import br.tec.facilitaservicos.criptografia.dominio.entidade.ChaveR2dbc;
import br.tec.facilitaservicos.criptografia.dominio.enums.StatusChave;
import br.tec.facilitaservicos.criptografia.dominio.enums.TipoChave;
import br.tec.facilitaservicos.criptografia.dominio.enums.AlgoritmosCriptograficos;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

/**
 * ============================================================================
 * 🗄️ REPOSITÓRIO REATIVO PARA CHAVES CRIPTOGRÁFICAS
 * ============================================================================
 * 
 * Repositório R2DBC para operações reativas com chaves criptográficas.
 * Fornece consultas otimizadas para:
 * 
 * 🔍 CONSULTAS ESPECIALIZADAS:
 * - Chaves por status, tipo e algoritmo
 * - Chaves expiradas e próximas do vencimento
 * - Chaves comprometidas ou revogadas
 * - Estatísticas de uso e performance
 * - Auditoria e compliance
 * 
 * ⚡ PERFORMANCE:
 * - Queries otimizadas com índices
 * - Paginação reativa
 * - Agregações eficientes
 * - Cache-friendly queries
 * 
 * 🛡️ SEGURANÇA:
 * - Multi-tenant isolation
 * - Access control queries
 * - Audit trail support
 * - Compliance reporting
 * 
 * @author Sistema de Migração R2DBC
 * @version 1.0
 * @since 2024
 */
@Repository
public interface ChaveRepository extends R2dbcRepository<ChaveR2dbc, String> {

    // === CONSULTAS POR STATUS ===

    /**
     * Busca chaves por status específico
     */
    Flux<ChaveR2dbc> findByStatusOrderByAtualizadoEmDesc(StatusChave status);

    /**
     * Busca chaves ativas por tenant
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE status = 'ATIVA' 
        AND tenant_id = :tenantId 
        AND ativo = true
        ORDER BY atualizado_em DESC
    """)
    Flux<ChaveR2dbc> findActiveKeysByTenant(String tenantId);

    /**
     * Busca chaves expiradas
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE valida_ate < :agora 
        AND status NOT IN ('EXPIRADA', 'REVOGADA', 'DESTRUIDA')
        ORDER BY valida_ate ASC
    """)
    Flux<ChaveR2dbc> findExpiredKeys(LocalDateTime agora);

    /**
     * Busca chaves próximas da expiração
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE valida_ate BETWEEN :agora AND :dataLimite
        AND status = 'ATIVA'
        ORDER BY valida_ate ASC
    """)
    Flux<ChaveR2dbc> findKeysNearExpiration(LocalDateTime agora, LocalDateTime dataLimite);

    /**
     * Conta chaves por status
     */
    @Query("SELECT COUNT(*) FROM chaves WHERE status = :status")
    Mono<Long> countByStatus(StatusChave status);

    // === CONSULTAS POR TIPO E ALGORITMO ===

    /**
     * Busca chaves por tipo
     */
    Flux<ChaveR2dbc> findByTipoOrderByCriadoEmDesc(TipoChave tipo);

    /**
     * Busca chaves por algoritmo
     */
    Flux<ChaveR2dbc> findByAlgoritmoOrderByCriadoEmDesc(AlgoritmosCriptograficos algoritmo);

    /**
     * Busca chaves por tipo e status
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE tipo = :tipo 
        AND status = :status
        AND ativo = true
        ORDER BY criado_em DESC
    """)
    Flux<ChaveR2dbc> findByTipoAndStatus(TipoChave tipo, StatusChave status);

    // === CONSULTAS DE ROTAÇÃO ===

    /**
     * Busca chaves que precisam de rotação
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE proxima_rotacao <= :agora
        AND status = 'ATIVA'
        AND politica_rotacao_dias > 0
        ORDER BY proxima_rotacao ASC
    """)
    Flux<ChaveR2dbc> findKeysForAutoRotation(LocalDateTime agora);

    /**
     * Busca chaves por versão (hierarquia)
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE chave_pai_id = :chavePaiId 
        OR id = :chavePaiId
        ORDER BY versao DESC
    """)
    Flux<ChaveR2dbc> findKeyVersions(String chavePaiId);

    /**
     * Busca versão mais recente de uma chave
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE (chave_pai_id = :chavePaiId OR id = :chavePaiId)
        ORDER BY versao DESC 
        LIMIT 1
    """)
    Mono<ChaveR2dbc> findLatestKeyVersion(String chavePaiId);

    // === CONSULTAS DE SEGURANÇA ===

    /**
     * Busca chaves comprometidas
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE status = 'COMPROMETIDA'
        ORDER BY atualizado_em DESC
    """)
    Flux<ChaveR2dbc> findCompromisedKeys();

    /**
     * Busca chaves com muitos alertas de segurança
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE alertas_seguranca >= :limitealertas
        AND status NOT IN ('REVOGADA', 'DESTRUIDA')
        ORDER BY alertas_seguranca DESC
    """)
    Flux<ChaveR2dbc> findKeysWithSecurityAlerts(int limiteAlertas);

    /**
     * Busca chaves com muitas falhas
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE contador_falhas >= :limiteFalhas
        AND status NOT IN ('REVOGADA', 'DESTRUIDA')
        ORDER BY contador_falhas DESC
    """)
    Flux<ChaveR2dbc> findKeysWithManyFailures(int limiteFalhas);

    // === CONSULTAS DE USAGE E METRICS ===

    /**
     * Busca chaves mais utilizadas
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE total_operacoes > 0
        ORDER BY total_operacoes DESC 
        LIMIT :limite
    """)
    Flux<ChaveR2dbc> findMostUsedKeys(int limite);

    /**
     * Busca chaves não utilizadas
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE (total_operacoes = 0 OR total_operacoes IS NULL)
        AND criado_em < :dataLimite
        AND status = 'ATIVA'
        ORDER BY criado_em ASC
    """)
    Flux<ChaveR2dbc> findUnusedKeys(LocalDateTime dataLimite);

    /**
     * Busca chaves que excederam limite de uso
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE usos_maximos IS NOT NULL 
        AND usos_atuais >= usos_maximos
        AND status NOT IN ('EXPIRADA', 'REVOGADA')
        ORDER BY usos_atuais DESC
    """)
    Flux<ChaveR2dbc> findKeysExceedingUsageLimit();

    // === CONSULTAS DE COMPLIANCE E AUDITORIA ===

    /**
     * Busca chaves por classificação de dados
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE classificacao_dados = :classificacao
        ORDER BY criado_em DESC
    """)
    Flux<ChaveR2dbc> findKeysByDataClassification(String classificacao);

    /**
     * Busca chaves por regulamentação
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE regulamentacoes LIKE CONCAT('%', :regulamentacao, '%')
        ORDER BY criado_em DESC
    """)
    Flux<ChaveR2dbc> findKeysByRegulation(String regulamentacao);

    /**
     * Busca chaves por país (data sovereignty)
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE pais_origem = :pais
        ORDER BY criado_em DESC
    """)
    Flux<ChaveR2dbc> findKeysByCountry(String pais);

    // === CONSULTAS DE LIMPEZA E MANUTENÇÃO ===

    /**
     * Busca chaves antigas revogadas para limpeza
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE status IN ('REVOGADA', 'DESTRUIDA')
        AND atualizado_em < :dataLimite
        ORDER BY atualizado_em ASC
    """)
    Flux<ChaveR2dbc> findOldRevokedKeys(LocalDateTime dataLimite);

    /**
     * Busca chaves para arquivamento
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE status IN ('SUBSTITUIDA', 'EXPIRADA')
        AND backup_permitido = true
        AND atualizado_em < :dataLimite
        ORDER BY atualizado_em ASC
    """)
    Flux<ChaveR2dbc> findKeysForArchival(LocalDateTime dataLimite);

    // === CONSULTAS PERSONALIZADAS COM FILTROS ===

    /**
     * Busca chaves com filtros customizados
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE (:tenantId IS NULL OR tenant_id = :tenantId)
        AND (:aplicacao IS NULL OR aplicacao = :aplicacao)
        AND (:tipo IS NULL OR tipo = :tipo)
        AND (:status IS NULL OR status = :status)
        AND (:ambiente IS NULL OR ambiente = :ambiente)
        AND ativo = true
        ORDER BY 
            CASE WHEN :ordenacao = 'nome' THEN nome END,
            CASE WHEN :ordenacao = 'data' THEN criado_em END DESC,
            CASE WHEN :ordenacao = 'uso' THEN total_operacoes END DESC,
            criado_em DESC
        LIMIT :limite OFFSET :offset
    """)
    Flux<ChaveR2dbc> findKeysComFiltros(
        String tenantId, String aplicacao, String tipo, String status, String ambiente,
        String ordenacao, int limite, int offset);

    /**
     * Conta chaves com filtros
     */
    @Query("""
        SELECT COUNT(*) FROM chaves 
        WHERE (:tenantId IS NULL OR tenant_id = :tenantId)
        AND (:aplicacao IS NULL OR aplicacao = :aplicacao)
        AND (:tipo IS NULL OR tipo = :tipo)
        AND (:status IS NULL OR status = :status)
        AND (:ambiente IS NULL OR ambiente = :ambiente)
        AND ativo = true
    """)
    Mono<Long> countKeysComFiltros(
        String tenantId, String aplicacao, String tipo, String status, String ambiente);

    // === CONSULTAS DE RELATÓRIOS E ESTATÍSTICAS ===

    /**
     * Estatísticas gerais de chaves
     */
    @Query("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN status = 'ATIVA' THEN 1 ELSE 0 END) as ativas,
            SUM(CASE WHEN status = 'REVOGADA' THEN 1 ELSE 0 END) as revogadas,
            SUM(CASE WHEN status = 'EXPIRADA' THEN 1 ELSE 0 END) as expiradas,
            AVG(CASE WHEN total_operacoes > 0 THEN total_operacoes ELSE NULL END) as media_operacoes
        FROM chaves 
        WHERE criado_em >= :dataInicio
    """)
    Mono<Object> getEstatisticasGerais(LocalDateTime dataInicio);

    /**
     * Estatísticas por tipo de chave
     */
    @Query("""
        SELECT 
            tipo,
            COUNT(*) as total,
            SUM(CASE WHEN status = 'ATIVA' THEN 1 ELSE 0 END) as ativas,
            AVG(CASE WHEN total_operacoes > 0 THEN total_operacoes ELSE NULL END) as media_operacoes,
            AVG(DATEDIFF(COALESCE(valida_ate, NOW()), criado_em)) as media_vida_dias
        FROM chaves 
        WHERE criado_em >= :dataInicio
        GROUP BY tipo
    """)
    Flux<Object> getEstatisticasPorTipo(LocalDateTime dataInicio);

    /**
     * Top chaves por bytes processados
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE total_bytes_processados > 0
        ORDER BY total_bytes_processados DESC
        LIMIT :limite
    """)
    Flux<ChaveR2dbc> findTopKeysByBytesProcessed(int limite);

    // === CONSULTAS DE BUSCA AVANÇADA ===

    /**
     * Busca chaves por fingerprint
     */
    @Query("SELECT * FROM chaves WHERE fingerprint = :fingerprint")
    Mono<ChaveR2dbc> findByFingerprint(String fingerprint);

    /**
     * Busca chaves por checksum
     */
    @Query("SELECT * FROM chaves WHERE checksum = :checksum")
    Flux<ChaveR2dbc> findByChecksum(String checksum);

    /**
     * Busca chaves por proprietário
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE proprietario = :proprietario
        OR criado_por = :proprietario
        ORDER BY criado_em DESC
    """)
    Flux<ChaveR2dbc> findKeysByOwner(String proprietario);

    /**
     * Busca chaves por tags
     */
    @Query("""
        SELECT * FROM chaves 
        WHERE tags LIKE CONCAT('%', :tag, '%')
        ORDER BY criado_em DESC
    """)
    Flux<ChaveR2dbc> findKeysByTag(String tag);

    /**
     * Busca duplicatas potenciais
     */
    @Query("""
        SELECT * FROM chaves c1
        WHERE EXISTS (
            SELECT 1 FROM chaves c2 
            WHERE c2.nome = c1.nome 
            AND c2.tenant_id = c1.tenant_id 
            AND c2.id != c1.id
            AND c2.status != 'REVOGADA'
        )
        ORDER BY nome, criado_em
    """)
    Flux<ChaveR2dbc> findPotentialDuplicates();

    // === OPERAÇÕES EM LOTE ===

    /**
     * Atualiza status de múltiplas chaves
     */
    @Query("""
        UPDATE chaves 
        SET status = :novoStatus, 
            status_anterior = status,
            motivo_mudanca_status = :motivo,
            atualizado_em = :agora
        WHERE id IN (:ids)
    """)
    Mono<Integer> updateStatusEmLote(java.util.List<String> ids, StatusChave novoStatus, 
                                    String motivo, LocalDateTime agora);

    /**
     * Marca chaves como expiradas
     */
    @Query("""
        UPDATE chaves 
        SET status = 'EXPIRADA',
            status_anterior = status,
            motivo_mudanca_status = 'Expiração automática',
            atualizado_em = :agora
        WHERE valida_ate < :agora
        AND status NOT IN ('EXPIRADA', 'REVOGADA', 'DESTRUIDA')
    """)
    Mono<Integer> markExpiredKeys(LocalDateTime agora);
}