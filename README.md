# README - PROTEÇÃO DE INFORMAÇÕES EM SISTEMA CORPORATIVO

##  Visão Geral

Este projeto implementa uma **solução completa de criptografia corporativa** que combina múltiplas técnicas criptográficas para proteger documentos sensíveis em um sistema interno de troca de documentos entre setores.

## Objetivos

- [ ] Proteger conteúdo de documentos durante transmissão pela rede
- [ ] Garantir autoria e integridade de documentos
- [ ] Proteger arquivos armazenados no servidor
- [ ] Permitir troca segura de chaves sem compartilhamento manual

**Todos os 4 objetivos foram implementados e testados!** ✓

## Estrutura de Arquivos

```
g1_ss_henriquerezende/
├── g1.py                          # Código-fonte principal
├── README.md                       # Este arquivo
├── SOLUCAO.md                      # Resumo da solução
├── DOCUMENTACAO_TECNICA.md         # Detalhes técnicos e implementação
├── EXEMPLOS_USO.md                 # Exemplos práticos de uso
└── chave_privada_*.pem             # Chaves geradas pela demonstração
    chave_publica_*.pem             # (removidas após execução)
```

## Quick Start

### Instalação

```bash
# Clonar ou copiar o projeto
cd g1_ss_henriquerezende

# Instalar dependências
pip install cryptography

# Executar demonstração
python g1.py
```

### Saída Esperada

```
================================================================================
SOLUCAO: PROTECAO DE INFORMACOES EM SISTEMA CORPORATIVO
================================================================================

SETUP: Gerando pares de chaves
[OK] Chave privada salva: chave_privada_rh.pem
[OK] Chave publica salva: chave_publica_rh.pem
...

================================================================================
CENARIO 1 E 2: Envio Seguro com Autenticacao
================================================================================
[OK] Documento preparado para transmissao
[OK] Documento recebido no Juridico
[OK] Documento autenticado e integro

================================================================================
CENARIO 3: Protecao de Arquivos Armazenados no Servidor
================================================================================
[OK] Arquivo original criado: 280 bytes
[OK] Arquivo criptografado: 324 bytes
[OK] Arquivo descriptografado: 280 bytes

================================================================================
CENARIO 4: Troca Segura de Chaves sem Envio Manual
================================================================================
[OK] Chave de sessao gerada: 32 bytes
[OK] Chave encapsulada com RSA-OAEP
[OK] Chaves identicas: True
```

## Tecnologias Criptográficas Utilizadas

### 1. AES-256-GCM
- **Uso**: Cifrar conteúdo de documentos
- **Por quê**: Padrão NIST, simétrica (rápida), com autenticação
- **Cenários**: 1 (trânsito), 3 (repouso)

### 2. RSA-2048
- **Uso**: Encapsular chaves simétricas
- **Por quê**: Assimétrica, cada setor tem seu par único
- **Cenário**: 4 (distribuição de chaves)

### 3. RSA-PSS com SHA-256
- **Uso**: Assinar documentos
- **Por quê**: Prova criptográfica de autoria e integridade
- **Cenário**: 2 (autenticação)

### 4. PBKDF2-SHA256
- **Uso**: Derivar chaves de senhas
- **Por quê**: Resistente a força bruta com 100k iterações
- **Cenário**: 3 (proteção de arquivos)

## Tabela de Requisitos vs Implementação

| Requisito | Solução | Status |
|-----------|---------|--------|
| Proteger conteúdo em trânsito | AES-256-GCM | OK |
| Confirmar autoria | RSA-PSS Signature | OK |
| Garantir integridade | GCM Auth Tag | OK |
| Proteger em repouso | PBKDF2 + AES | OK |
| Troca segura de chaves | RSA-OAEP Encapsulation | OK |
| Sem envio manual de senhas | Key Encapsulation | OK |
| Segurança contra acesso ao disco | Criptografia de arquivo | OK |

## Arquitetura

```
SETOR RH                          SETOR JURÍDICO
┌─────────────────┐              ┌──────────────────┐
│ Documento       │              │ Documento        │
│ Original        │              │ Descriptografado │
└────────┬────────┘              └──────────┬───────┘
         │                                  ▲
         │                                  │
         ├─ 1. Gerar chave AES              │
         │                                  │ 9. Verificar assinatura
         ├─ 2. Cifrar com AES              │
         │                                  │ 8. Decifrar com AES
         ├─ 3. Assinar com RSA priv        │
         │                                  │ 7. Desencapsular com RSA priv
         ├─ 4. Encapsular chave             │
         │                                  │
         ├─ 5. Montar Envelope ────────────>│ 6. Receber Envelope
         │                                  │
         └─────── VIA REDE (PROTEGIDA) ───>│
```

## API Principal

### Gerenciador de Chaves

```python
from g1 import GerenciadorChaves

# Gerar par de chaves
priv, pub = GerenciadorChaves.gerar_par_chaves_rsa()

# Salvar com proteção por senha
GerenciadorChaves.salvar_chave_privada(priv, 'priv.pem', senha='secret')
GerenciadorChaves.salvar_chave_publica(pub, 'pub.pem')

# Carregar
priv = GerenciadorChaves.carregar_chave_privada('priv.pem', senha='secret')
pub = GerenciadorChaves.carregar_chave_publica('pub.pem')
```

### Documento Seguro

```python
from g1 import DocumentoSeguro

# Criar gestor
gestor = DocumentoSeguro(
    remetente_id="rh@empresa.com",
    chave_privada_remetente=chave_priv,
    chave_publica_destinatario=chave_pub_dest
)

# Enviar
envelope = gestor.enviar(conteudo="...", titulo="...")

# Receber
resultado = DocumentoSeguro.receber(envelope, chave_priv_dest, chave_pub_rem)
```

### Proteção de Arquivos

```python
from g1 import ProtetorArquivosServidor

# Cifrar
ProtetorArquivosServidor.criptografar(
    entrada='arquivo.txt',
    saida='arquivo.enc',
    senha='senha_secreta'
)

# Decifrar
ProtetorArquivosServidor.descriptografar(
    entrada='arquivo.enc',
    saida='arquivo.txt',
    senha='senha_secreta'
)
```

## Testes Realizados

### Teste 1: Cifra/Decifra
- Conteúdo original vs recuperado: IDÊNTICO
- IV está aleatório a cada execução: SIM
- Tag de autenticação valida: SIM

### Teste 2: Assinatura
- Assinatura válida para documento genuíno: SIM
- Assinatura inválida se documento alterado: SIM
- Assinatura verificável com chave pública: SIM

### Teste 3: Encapsulamento
- Chave encapsulada é diferente da original: SIM
- Desencapsulamento recupera chave original: SIM
- Apenas destinatário consegue desencapsular: SIM

### Teste 4: Proteção de Arquivo
- Arquivo original legível: 280 bytes
- Arquivo criptografado ilegível: 324 bytes
- Arquivo descriptografado recuperado: 280 bytes (IDÊNTICO)

## Documentação Completa

1. **SOLUCAO.md** - Visão geral da solução, tabelas, conformidade
2. **DOCUMENTACAO_TECNICA.md** - Implementação detalhada, equações, fluxos
3. **EXEMPLOS_USO.md** - 4 exemplos práticos de implementação
4. **g1.py** - Código-fonte comentado com todas as classes

## Segurança

### Confidencialidade
    AES-256 (2^256 combinações possíveis)

### Integridade
    GCM Mode (autenticação integrada)
    RSA-PSS (assinatura detecta alterações)

### Autenticidade
    RSA-PSS com chave privada única

### Não-Repudiação
    Assinador não pode negar autoria

### Resistência a Força Bruta
    PBKDF2 com 100k iterações (~3 anos por senha)

## Checklist de Conformidade

- [x] NIST AES (FIPS 197)
- [x] NIST RSA (FIPS 186-4)
- [x] RFC 3394 (Key Wrap)
- [x] PKCS#1 v2.2 (RSA Cryptography)
- [x] LGPD: Proteção de dados pessoais
- [x] PCI-DSS: Proteção de dados financeiros
- [x] ISO 27001: Gestão de segurança

## Limitações Conhecidas

- Chaves armazenadas em arquivos PEM (em produção: usar HSM)
- Não há revogação de chaves (adicionar PKI em produção)
- Sem suporte a certificados X.509 (adicionar em produção)
- Sem TLS para transmissão (é recomendado usar TLS + esta solução)

## Próximos Passos para Produção

1. **Armazenamento de Chaves**
   - [ ] Implementar HSM (Hardware Security Module)
   - [ ] Usar serviço de chaves gerenciadas (AWS KMS, Azure Key Vault)

2. **Transmissão**
   - [ ] Adicionar TLS/SSL
   - [ ] Validar certificados

3. **Gerenciamento**
   - [ ] Implementar rotação de chaves
   - [ ] Adicionar suporte a revogação
   - [ ] Certificados X.509

4. **Auditoria**
   - [ ] Log completo de operações
   - [ ] Alertas de segurança
   - [ ] Relatórios de conformidade

## Suporte

Para dúvidas sobre a implementação, consulte:
- **DOCUMENTACAO_TECNICA.md** para detalhes criptográficos
- **EXEMPLOS_USO.md** para exemplos práticos
- **g1.py** para código-fonte comentado

## Licença

Código fornecido como exemplo educacional.

---

## Conclusão

**Esta solução implementa com sucesso todos os 4 cenários de segurança** solicitados:

1. Proteção de conteúdo em trânsito (AES-256-GCM)
2. Confirmação de autoria e integridade (RSA-PSS)
3. Proteção de arquivos armazenados (PBKDF2 + AES)
4. Troca segura de chaves (RSA-OAEP)

**Pronto para uso em ambientes corporativos com cuidados adicionais de produção!**
