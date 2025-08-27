# 📚 LIÇÕES APRENDIDAS - MICROSERVIÇO CRIPTOGRAFIA

> **INSTRUÇÕES PARA AGENTES DE IA:** Este arquivo contém lições aprendidas críticas deste microserviço. SEMPRE atualize este arquivo após resolver problemas, implementar correções ou descobrir melhores práticas.

---

## 🎯 **METADADOS DO MICROSERVIÇO**
- **Nome:** conexao-de-sorte-backend-criptografia
- **Responsabilidade:** Criptografia de dados, hashing, chaves
- **Tecnologias:** Spring Boot 3.5.5, WebFlux, R2DBC, Java 24
- **Última Atualização:** 2025-08-27

---

## ✅ **CORREÇÕES APLICADAS (2025-08-27)**

### 📦 **1. Spring Boot Desatualizado**
**Problema:** Versão desatualizada 3.4.1 (vulnerabilidades + bugs)
**Solução:** Atualizado para 3.5.5 (versão estável atual)
**Lição:** Manter Spring Boot sempre na versão estável mais recente

---

## 🎯 **BOAS PRÁTICAS IDENTIFICADAS**

### ✅ **Versionamento Consistente:**
- Spring Boot: 3.5.5 (padronizado em todo ecosystem)
- Java: 24 (compatível com performance otimizada)
- Dependências: Sempre usar versões estáveis (não SNAPSHOT)

---

## 📋 **CHECKLIST PARA FUTURAS ALTERAÇÕES**

**Versionamento:**
- [ ] Spring Boot = 3.5.5 (alinhado com outros microserviços)
- [ ] Java = 24 (compatibilidade garantida)
- [ ] Dependências sem SNAPSHOT em produção

**Segurança (Crítico para Criptografia):**
- [ ] Algoritmos criptográficos atualizados
- [ ] Chaves nunca hardcoded
- [ ] Logs não expõem dados sensíveis

---

*📝 Arquivo gerado automaticamente em 2025-08-27 por Claude Code*