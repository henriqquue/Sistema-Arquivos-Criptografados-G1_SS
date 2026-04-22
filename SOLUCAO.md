# SOLUÇÃO: PROTEÇÃO DE INFORMAÇÕES EM SISTEMA CORPORATIVO

## Visão Geral

Esta solução implementa um sistema completo de proteção de informações combinando:
- **Criptografia Simétrica** (AES-256-GCM)
- **Criptografia Assimétrica** (RSA-2048)
- **Assinatura Digital** (RSA-PSS com SHA-256)
- **Derivação de Chaves** (PBKDF2-SHA256)

## Cenários de Segurança Cobertos

### CENÁRIO 1: Proteção de Conteúdo em Trânsito
**Problema**: Documentos precisam estar protegidos enquanto trafegam pela rede

**Solução**: 
- AES-256-GCM cifra o conteúdo com uma chave simétrica aleatória
- Modo GCM fornece autenticação integrada
- Impossível ler o conteúdo se interceptado

**Resultado**: 
```
[OK] Documento preparado para transmissao
Conteudo: [CIFRADO] 1OfClgqa+UpoA1p2tsdgJMObhRW1YrexY53bDQuq...
```

### CENÁRIO 2: Confirmação de Autoria e Integridade
**Problema**: Como garantir que documento foi enviado por quem diz e não foi alterado?

**Solução**:
- RSA-PSS assina o documento original com chave privada do remetente
- Assinatura é imutável - qualquer alteração invalida
- Prova criptográfica de autoria (não repudiação)

**Resultado**:
```
Status: [OK] Autenticado
Assinatura valida: True
```

### CENÁRIO 3: Proteção de Arquivos Armazenados
**Problema**: Arquivos no servidor precisam estar protegidos mesmo em caso de acesso indevido ao disco

**Solução**:
- PBKDF2 deriva chave forte de senha
- AES-256-GCM cifra arquivo
- Salt armazenado junto (permite descifragem com mesma senha)
- Arquivo criptografado é ilegível mesmo com acesso físico

**Resultado**:
```
[OK] Arquivo original: 280 bytes (LEGÍVEL)
[OK] Arquivo criptografado: 324 bytes (ILEGÍVEL)
[OK] Arquivo recuperado: Legível novamente
```

### CENÁRIO 4: Troca Segura de Chaves sem Envio Manual
**Problema**: Como compartilhar chave de sessão sem enviar por email/planilha?

**Solução**:
- RSA-OAEP encapsula chave simétrica com chave pública do destinatário
- Apenas quem tem chave privada correspondente consegue desencapsular
- Chave pública pode ser compartilhada abertamente
- Elimina necessidade de envio manual de segredos

**Resultado**:
```
[OK] Chave de sessao gerada: 32 bytes
[OK] Chave encapsulada com RSA-OAEP
>>> Chaves identicas: True (somenta o destinatario desencapsulou)
```

## Fluxo Integrado Seguro

```
REMETENTE (RH) ──────────────────> DESTINATÁRIO (JURÍDICO)

1. RH gera chave simétrica aleatória (AES-256)
2. RH cifra documento com essa chave
3. RH assina documento com sua chave privada
4. RH encapsula a chave AES com chave pública do Jurídico
5. RH envia: [ciphertext + assinatura + chave_encapsulada]
   ↓ PELA REDE (PROTEGIDA) ↓
6. Jurídico recebe envelope protegido
7. Jurídico desencapsula com sua chave privada
8. Jurídico decifra conteúdo com chave simétrica
9. Jurídico verifica assinatura ✓ AUTENTICADO
```

## Componentes Criptográficos

### 1. AES-256-GCM (Criptografia Simétrica)
- **Por quê**: Padrão NIST, rápido, eficiente
- **Autenticação integrada**: Modo GCM detecta alterações
- **Uso**: Cidra conteúdo (cenários 1 e 3)
- **Chave**: 256 bits (gerada aleatoriamente)

### 2. RSA-2048 (Criptografia Assimétrica)  
- **Por quê**: Permite encapsular chaves sem compartilhar secretos
- **Par de chaves**: Chave privada (protegida) + Chave pública (compartilhável)
- **Uso**: Encapsula chave simétrica (cenário 4)
- **Padding**: OAEP (resistente a ataques)

### 3. RSA-PSS com SHA-256 (Assinatura Digital)
- **Por quê**: Prova criptográfica de autoria
- **Não repudiação**: Assinador não pode negar
- **Uso**: Prova autoria e integridade (cenário 2)
- **Hash**: SHA-256 (seguro, rápido)

### 4. PBKDF2-SHA256 (Derivação de Chaves)
- **Por quê**: Converte senhas em chaves fortes resitentes a força bruta
- **Uso**: Proteção de arquivos no servidor (cenário 3)
- **Iterações**: 100.000 (segurança contra força bruta)
- **Salt**: Armazenado com arquivo (permite descifragem)

## Conformidade com Requisitos

| Requisito | Implementação | Status |
|-----------|---------------|--------|
| Conteúdo protegido em trânsito | AES-256-GCM | ✓ OK |
| Confirmação de autoria | RSA-PSS Assinatura | ✓ OK |
| Integridade garantida | GCM Authentication | ✓ OK |
| Proteção em repouso | AES-256 + PBKDF2 | ✓ OK |
| Troca segura de chaves | RSA-OAEP Encapsulamento | ✓ OK |
| Sem envio manual de senhas | Key Encapsulation | ✓ OK |
| Acesso ao disco não expõe dados | Criptografia de arquivo | ✓ OK |

## Estrutura do Código

```
g1.py
├── GerenciadorChaves
│   ├── gerar_par_chaves_rsa()
│   ├── salvar_chave_privada()
│   └── salvar_chave_publica()
├── CriptografiaSimetrica
│   ├── gerar_chave()
│   ├── cifrar()
│   └── decifrar()
├── AssinaturaDigital
│   ├── assinar()
│   └── verificar()
├── EncapsulamentoChaves
│   ├── encapsular()
│   └── desencapsular()
├── DocumentoSeguro
│   ├── enviar()
│   └── receber()
├── ProtetorArquivosServidor
│   ├── derivar_chave()
│   ├── criptografar()
│   └── descriptografar()
└── demonstracao()
```

## Como Usar

```bash
python g1.py
```

A demonstração:
1. Gera pares de chaves RSA para RH e Jurídico
2. RH envia contrato de trabalho protegido para Jurídico
3. Jurídico recebe e valida o documento
4. Protege arquivo estratégico no servidor
5. Demonstra troca segura de chaves simétricas
6. Mostra resumo de segurança e conformidade

## Segurança da Solução

✓ **Confidencialidade**: AES-256 cifra conteúdo
✓ **Integridade**: GCM-Mode e RSA-PSS detectam alterações  
✓ **Autenticidade**: Assinatura digital prova origem
✓ **Não-repudiação**: Assinador não pode negar
✓ **Proteção em repouso**: PBKDF2 + AES protegem arquivos
✓ **Gerenciamento de chaves**: RSA-OAEP elimina compartilhamento manual

## Dependências

```
cryptography>=41.0.0
```

Instalação:
```bash
pip install cryptography
```

## Conclusão

Esta solução integra de forma harmônica os componentes de criptografia para:
1. Proteger documentos durante transmissão
2. Garantir autoria e integridade
3. Proteger arquivos armazenados
4. Permitir troca segura de chaves sem riscos

Todos os 4 cenários foram cobertos com sucesso e testados!
