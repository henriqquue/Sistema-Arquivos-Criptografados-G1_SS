# EXEMPLOS DE USO - CASOS PRÁTICOS

## Exemplo 1: Enviar Contrato RH → Jurídico

```python
from g1 import (
    GerenciadorChaves,
    DocumentoSeguro,
    CriptografiaSimetrica,
    AssinaturaDigital,
    EncapsulamentoChaves
)

# PASSO 1: Criar chaves para os setores (uma única vez)
print("[SETUP] Gerando chaves RSA...")
chave_priv_rh, chave_pub_rh = GerenciadorChaves.gerar_par_chaves_rsa()
chave_priv_jur, chave_pub_jur = GerenciadorChaves.gerar_par_chaves_rsa()

# Salvar chaves (com proteção por senha)
GerenciadorChaves.salvar_chave_privada(
    chave_priv_rh, 
    '/secure/rh/chave_privada.pem',
    senha='senha_super_secreta_rh'
)
GerenciadorChaves.salvar_chave_publica(
    chave_pub_rh,
    '/public/rh/chave_publica.pem'  # Pode ser distribuída
)

# Similar para Jurídico...

# PASSO 2: RH prepara documento para envio
print("[RH] Preparando contrato para envio...")

# Carregar chaves (em produção: do HSM)
chave_priv_rh = GerenciadorChaves.carregar_chave_privada(
    '/secure/rh/chave_privada.pem',
    senha='senha_super_secreta_rh'
)

# Criar gestor de documentos RH
gestor_rh = DocumentoSeguro(
    remetente_id="rh@empresa.com",
    chave_privada_remetente=chave_priv_rh,
    chave_publica_destinatario=chave_pub_jur  # Pública - pode ser obtida de servidor
)

# Preparar contrato
contrato = """CONTRATO DE TRABALHO
Empresa: Acme Corp
Data: 22/04/2026
Funcionário: João Silva
CPF: 123.456.789-00
Cargo: Analista de Sistemas
Departamento: TI

Remuneração:
- Salário: R$ 5.000,00
- Vale-transporte: R$ 150,00
- Vale-refeição: R$ 300,00

Benefícios:
- Plano de saúde
- Odontológico
- Seguro de vida

Assinado digitalmente em 22/04/2026"""

# Enviar documento
envelope = gestor_rh.enviar(
    conteudo=contrato,
    titulo="Contrato João Silva"
)

print(f"[OK] Envelope criado")
print(f"  - Tamanho ciphertext: {len(envelope['ciphertext'])} caracteres")
print(f"  - Tamanho chave_encapsulada: {len(envelope['chave_encapsulada'])} caracteres")

# PASSO 3: Transmitir envelope pela rede
print("[REDE] Enviando envelope protegido...")
# envelope_json = json.dumps(envelope)
# requests.post('https://juridico.empresa.com/documentos', data=envelope_json)

# PASSO 4: Jurídico recebe e processa
print("[JURÍDICO] Recebendo documento...")

resultado = DocumentoSeguro.receber(
    envelope=envelope,
    chave_privada_destinatario=chave_priv_jur,
    chave_publica_remetente=chave_pub_rh
)

if resultado['sucesso']:
    print(f"[OK] Documento processado")
    print(f"  Status: {resultado['msg']}")
    print(f"  Remetente: {resultado['remetente']}")
    print(f"  Assinatura válida: {resultado['assinatura_valida']}")
    
    if resultado['assinatura_valida']:
        print("\n[OK] DOCUMENTO AUTENTICADO!")
        print(f"\nConteúdo:\n{resultado['conteudo']}")
        
        # Guardar contrato criptografado no servidor
        with open('contrato_assinado.enc', 'wb') as f:
            f.write(json.dumps(envelope).encode())
    else:
        print("[!] AVISO: Assinatura inválida - documento pode ter sido alterado!")
```

---

## Exemplo 2: Proteger Documento Estratégico no Servidor

```python
from g1 import ProtetorArquivosServidor
import os

# PASSO 1: Documento original criado por usuário
documento_original = """PLANEJAMENTO ESTRATÉGICO 2027-2030
NÍVEL: CONFIDENCIAL

Objetivos:
1. Expansão para mercados internacionais
2. Desenvolvimento de novos produtos
3. Otimização de custos operacionais

Investimentos Previstos:
- Infraestrutura: R$ 2 milhões
- P&D: R$ 1.5 milhões
- Marketing: R$ 800 mil

Previsão de Lucro: R$ 50 milhões

NÃO COMPARTILHAR EXTERNAMENTE"""

# Salvar documento original
with open('planejamento_2027.txt', 'w') as f:
    f.write(documento_original)

print(f"[OK] Documento original criado: 280 bytes")
print(f"  Conteúdo: LEGÍVEL em texto plano")

# PASSO 2: Criptografar para armazenamento
print("\n[CRIPTOGRAFIA] Protegendo arquivo...")

ProtetorArquivosServidor.criptografar(
    entrada='planejamento_2027.txt',
    saida='planejamento_2027.enc',
    senha='senha_forte_do_servidor_2027'
)

print(f"[OK] Arquivo criptografado: 324 bytes")
print(f"  Conteúdo: ILEGÍVEL (mesmo com acesso ao disco)")

# Função: Verificar integridade de arquivo criptografado
def verificar_integridade_arquivo(caminho_enc):
    """Verifica se arquivo criptografado é válido"""
    import hashlib
    with open(caminho_enc, 'rb') as f:
        dados = f.read()
    
    # Hash do arquivo
    hash_arquivo = hashlib.sha256(dados).hexdigest()
    print(f"[INFO] Hash SHA256 do arquivo: {hash_arquivo}")
    
    # Verificar tamanho mínimo
    if len(dados) < 60:  # 16 (salt) + 12 (iv) + 16 (tag) + conteúdo
        print("[!] AVISO: Arquivo muito pequeno - pode estar corrompido")
        return False
    
    print("[OK] Arquivo aparenta estar íntegro")
    return True

verificar_integridade_arquivo('planejamento_2027.enc')

# PASSO 3: Usuário autorizado desencripta quando necessário
print("\n[ACESSO] Usuário autorizado solicitando documento...")

senha_usuario = 'senha_forte_do_servidor_2027'

# Verificar se senha está correta
try:
    ProtetorArquivosServidor.descriptografar(
        entrada='planejamento_2027.enc',
        saida='planejamento_2027_recuperado.txt',
        senha=senha_usuario
    )
    print("[OK] Arquivo descriptografado com sucesso!")
    
    # Ler conteúdo
    with open('planejamento_2027_recuperado.txt', 'r') as f:
        conteudo = f.read()
    
    print("\n[OK] Conteúdo recuperado:")
    print(conteudo)
    
    # Registrar acesso em log de auditoria
    print("\n[LOG] Acesso registrado em auditoria:")
    print(f"  - Usuário: admin@empresa.com")
    print(f"  - Arquivo: planejamento_2027.enc")
    print(f"  - Timestamp: 2026-04-22 10:30:45")
    print(f"  - Ação: DESCRIPTOGRAFE")
    
except Exception as e:
    print(f"[ERRO] Falha ao descriptografar: {e}")
    print("[!] AVISO: Conta de acesso bloqueada por segurança")

# Limpeza
print("\n[LIMPEZA] Removendo arquivo temporário...")
os.remove('planejamento_2027_recuperado.txt')
```

---

## Exemplo 3: Automatizar Troca de Chaves

```python
from g1 import (
    GerenciadorChaves,
    CriptografiaSimetrica,
    EncapsulamentoChaves
)
import json

class CentralizadorChaves:
    """Gerencia distribuição segura de chaves entre setores"""
    
    def __init__(self):
        self.setores = {}
        self.chaves_sessao = {}
    
    def registrar_setor(self, nome_setor, chave_publica):
        """Registra novo setor com sua chave pública"""
        self.setores[nome_setor] = {
            'chave_publica': chave_publica,
            'registrado_em': datetime.now().isoformat()
        }
        print(f"[OK] Setor '{nome_setor}' registrado")
    
    def criar_chave_sessao_para_setor(self, nome_setor):
        """Cria chave de sessão encapsulada para setor específico"""
        if nome_setor not in self.setores:
            raise ValueError(f"Setor '{nome_setor}' não registrado")
        
        # Gerar chave simétrica aleatória
        chave_simetrica = CriptografiaSimetrica.gerar_chave()
        
        # Encapsular com chave pública do setor
        chave_encapsulada = EncapsulamentoChaves.encapsular(
            chave_simetrica,
            self.setores[nome_setor]['chave_publica']
        )
        
        # Armazenar para fornecimento seguro
        self.chaves_sessao[nome_setor] = {
            'chave_encapsulada': chave_encapsulada,
            'criada_em': datetime.now().isoformat(),
            'tamanho_bytes': len(chave_simetrica)
        }
        
        print(f"[OK] Chave de sessão criada para '{nome_setor}'")
        print(f"  - Tamanho chave: {len(chave_simetrica)} bytes")
        print(f"  - Tamanho encapsulada: {len(chave_encapsulada)} caracteres")
        
        return chave_encapsulada
    
    def distribuir_chave_para_setor(self, nome_setor):
        """Distribui chave de sessão de forma segura"""
        if nome_setor not in self.chaves_sessao:
            chave_encapsulada = self.criar_chave_sessao_para_setor(nome_setor)
        else:
            chave_encapsulada = self.chaves_sessao[nome_setor]['chave_encapsulada']
        
        # Retornar via HTTPS/TLS
        resposta = {
            'setor': nome_setor,
            'chave_encapsulada': chave_encapsulada,
            'algoritmo': 'RSA-2048-OAEP',
            'instrucoes': 'Desencapsule com sua chave privada'
        }
        
        print(f"\n[DISTRIBUIÇÃO] Enviando chave para '{nome_setor}'")
        print(f"  - Via: HTTPS/TLS")
        print(f"  - JSON length: {len(json.dumps(resposta))} bytes")
        
        return resposta

# USO DO CENTRALIZADOR

from datetime import datetime

print("[SETUP] Criando Centralizador de Chaves...\n")
centralizador = CentralizadorChaves()

# Gerar chaves para cada setor
print("[SETUP] Gerando pares de chaves por setor...\n")
setores = ['RH', 'Jurídico', 'Financeiro', 'TI']

chaves_setores = {}
for setor in setores:
    priv, pub = GerenciadorChaves.gerar_par_chaves_rsa()
    chaves_setores[setor] = {'priv': priv, 'pub': pub}
    centralizador.registrar_setor(setor, pub)

# Criar e distribuir chaves de sessão
print("\n[OPERAÇÃO] Distribuindo chaves de sessão...\n")

for setor in setores:
    chave_encap = centralizador.criar_chave_sessao_para_setor(setor)
    resposta = centralizador.distribuir_chave_para_setor(setor)
    
    # Simular desencapsulamento no setor
    print(f"\n[{setor}] Recebendo e desencapsulando...")
    chave_recuperada = EncapsulamentoChaves.desencapsular(
        chave_encap,
        chaves_setores[setor]['priv']
    )
    print(f"[{setor}] Chave desencapsulada com sucesso!")
    print(f"  - Tamanho: {len(chave_recuperada)} bytes")
    print(f"  - Pronta para uso")

print("\n[OK] Distribuição de chaves concluída!")
print("[OK] Todos os setores têm chaves de sessão únicas e seguras")
```

---

## Exemplo 4: Auditoria de Operações Criptográficas

```python
from datetime import datetime
import json
import hashlib

class AuditoriaSeguranca:
    """Registra todas as operações criptográficas"""
    
    def __init__(self, arquivo_log='auditoria_seguranca.log'):
        self.arquivo_log = arquivo_log
        self.eventos = []
    
    def registrar_evento(self, tipo, setor, operacao, status, detalhes=None):
        """Registra evento de segurança"""
        evento = {
            'timestamp': datetime.now().isoformat(),
            'tipo': tipo,
            'setor': setor,
            'operacao': operacao,
            'status': status,
            'detalhes': detalhes or {},
            'usuario_ip': '192.168.1.100'  # Em produção: obter request IP
        }
        
        self.eventos.append(evento)
        
        # Salvar em arquivo
        with open(self.arquivo_log, 'a') as f:
            f.write(json.dumps(evento) + '\n')
        
        return evento
    
    def gerar_relatorio(self):
        """Gera relatório de atividades"""
        relatorio = {
            'total_eventos': len(self.eventos),
            'eventos_por_tipo': {},
            'eventos_por_setor': {},
            'status': {}
        }
        
        for evento in self.eventos:
            # Contar por tipo
            t = evento['tipo']
            relatorio['eventos_por_tipo'][t] = relatorio['eventos_por_tipo'].get(t, 0) + 1
            
            # Contar por setor
            s = evento['setor']
            relatorio['eventos_por_setor'][s] = relatorio['eventos_por_setor'].get(s, 0) + 1
            
            # Contar por status
            st = evento['status']
            relatorio['status'][st] = relatorio['status'].get(st, 0) + 1
        
        return relatorio

# USO

print("[AUDITORIA] Iniciando log de segurança\n")
auditoria = AuditoriaSeguranca()

# Registrar operações
auditoria.registrar_evento(
    tipo='CIFRAGE',
    setor='RH',
    operacao='cifrar_documento',
    status='SUCESSO',
    detalhes={'tamanho_plaintext': 1024, 'algoritmo': 'AES-256-GCM'}
)

auditoria.registrar_evento(
    tipo='ASSINATURA',
    setor='RH',
    operacao='assinar_contrato',
    status='SUCESSO',
    detalhes={'documento': 'contrato_joao_silva.docx'}
)

auditoria.registrar_evento(
    tipo='ENCAPSULAMENTO',
    setor='Jurídico',
    operacao='desencapsular_chave',
    status='SUCESSO',
    detalhes={'tamanho_chave': 32}
)

auditoria.registrar_evento(
    tipo='DESCRIPTOGRAFIA',
    setor='Financeiro',
    operacao='descriptografar_arquivo',
    status='SUCESSO',
    detalhes={'arquivo': 'planilha_salarios.xlsx.enc'}
)

auditoria.registrar_evento(
    tipo='ACESSO',
    setor='TI',
    operacao='acesso_negado_chave_privada',
    status='FALHA',
    detalhes={'motivo': 'senha_incorreta', 'tentativas': 3}
)

# Gerar relatório
print("[RELATÓRIO] Eventos de Segurança\n")
relatorio = auditoria.gerar_relatorio()

print(f"Total de eventos: {relatorio['total_eventos']}\n")

print("Eventos por tipo:")
for tipo, count in relatorio['eventos_por_tipo'].items():
    print(f"  - {tipo}: {count}")

print("\nEventos por setor:")
for setor, count in relatorio['eventos_por_setor'].items():
    print(f"  - {setor}: {count}")

print("\nStatus:")
for status, count in relatorio['status'].items():
    print(f"  - {status}: {count}")

print("\n[OK] Log de auditoria concluído!")
```

---

## Resumo de Boas Práticas

### ✓ DO
- Usar chaves fortes (RSA-2048+, AES-256)
- Gerar IVs aleatórios para cada conversação
- Salvar chaves privadas criptografadas
- Registrar todas as operações em auditoria
- Usar apenas bibliotecas criptográficas estabelecidas (cryptography)
- Validar assinaturas sempre que receber dados
- Chamar destruir chaves sensíveis após usar

### ✗ DON'T
- Reutilizar IVs (quebra segurança GCM)
- Armazenar chaves em plaintext
- Usar senhas fracas para derivação
- Ignorar erros de verifiação de assinatura
- Inventar algoritmos criptográficos
- Compartilhar chaves privadas
- Implementar criptografia manualmente

Boa sorte com a implementação!
