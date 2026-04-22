# -*- coding: utf-8 -*-
"""
SOLUCAO: PROTECAO DE INFORMACOES EM SISTEMA CORPORATIVO
Criptografia Simetrica, Assimetrica e Assinatura Digital

Cenarios cobertos:
1. Protecao de conteudo em transito
2. Confirmacao de autoria e integridade
3. Protecao de arquivos armazenados
4. Troca segura de chaves sem envio manual
"""

import os
import json
import base64
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class GerenciadorChaves:
    @staticmethod
    def gerar_par_chaves_rsa(tamanho=2048):
        chave_priv = rsa.generate_private_key(
            public_exponent=65537,
            key_size=tamanho,
            backend=default_backend()
        )
        return chave_priv, chave_priv.public_key()
    
    @staticmethod
    def salvar_chave_privada(chave, caminho, senha=None):
        enc = serialization.BestAvailableEncryption(senha.encode()) if senha else serialization.NoEncryption()
        pem = chave.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc
        )
        with open(caminho, 'wb') as f:
            f.write(pem)
        print(f"[OK] Chave privada salva: {caminho}")
    
    @staticmethod
    def salvar_chave_publica(chave, caminho):
        pem = chave.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(caminho, 'wb') as f:
            f.write(pem)
        print(f"[OK] Chave publica salva: {caminho}")


class CriptografiaSimetrica:
    @staticmethod
    def gerar_chave(bits=256):
        return os.urandom(bits // 8)
    
    @staticmethod
    def cifrar(conteudo, chave):
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(chave), modes.GCM(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(conteudo.encode()) + enc.finalize()
        return {
            'iv': base64.b64encode(iv).decode(),
            'ciphertext': base64.b64encode(ct).decode(),
            'tag': base64.b64encode(enc.tag).decode()
        }
    
    @staticmethod
    def decifrar(dados, chave):
        iv = base64.b64decode(dados['iv'])
        ct = base64.b64decode(dados['ciphertext'])
        tag = base64.b64decode(dados['tag'])
        cipher = Cipher(algorithms.AES(chave), modes.GCM(iv, tag), backend=default_backend())
        dec = cipher.decryptor()
        return (dec.update(ct) + dec.finalize()).decode()


class AssinaturaDigital:
    @staticmethod
    def assinar(conteudo, chave_priv):
        assinatura = chave_priv.sign(
            conteudo.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(assinatura).decode()
    
    @staticmethod
    def verificar(conteudo, assinatura_b64, chave_pub):
        try:
            chave_pub.verify(
                base64.b64decode(assinatura_b64),
                conteudo.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False


class EncapsulamentoChaves:
    @staticmethod
    def encapsular(chave, chave_pub):
        ct = chave_pub.encrypt(
            chave,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ct).decode()
    
    @staticmethod
    def desencapsular(chave_b64, chave_priv):
        return chave_priv.decrypt(
            base64.b64decode(chave_b64),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


class DocumentoSeguro:
    def __init__(self, remetente, chave_priv, chave_pub_dest):
        self.remetente = remetente
        self.chave_priv = chave_priv
        self.chave_pub_dest = chave_pub_dest
    
    def enviar(self, conteudo, titulo):
        chave = CriptografiaSimetrica.gerar_chave()
        dados_cif = CriptografiaSimetrica.cifrar(conteudo, chave)
        assinatura = AssinaturaDigital.assinar(conteudo, self.chave_priv)
        chave_encap = EncapsulamentoChaves.encapsular(chave, self.chave_pub_dest)
        
        return {
            'titulo': titulo,
            'remetente': self.remetente,
            'timestamp': datetime.now().isoformat(),
            'iv': dados_cif['iv'],
            'ciphertext': dados_cif['ciphertext'],
            'tag': dados_cif['tag'],
            'assinatura': assinatura,
            'chave_encapsulada': chave_encap
        }
    
    @staticmethod
    def receber(envelope, chave_priv_dest, chave_pub_rem):
        try:
            chave = EncapsulamentoChaves.desencapsular(
                envelope['chave_encapsulada'],
                chave_priv_dest
            )
            dados_cif = {
                'iv': envelope['iv'],
                'ciphertext': envelope['ciphertext'],
                'tag': envelope['tag']
            }
            conteudo = CriptografiaSimetrica.decifrar(dados_cif, chave)
            assinatura_ok = AssinaturaDigital.verificar(
                conteudo,
                envelope['assinatura'],
                chave_pub_rem
            )
            
            return {
                'sucesso': True,
                'titulo': envelope['titulo'],
                'remetente': envelope['remetente'],
                'conteudo': conteudo,
                'assinatura_valida': assinatura_ok,
                'msg': '[OK] Autenticado' if assinatura_ok else '[AVISO] Assinatura invalida'
            }
        except Exception as e:
            return {'sucesso': False, 'erro': str(e)}


class ProtetorArquivosServidor:
    @staticmethod
    def derivar_chave(senha, salt=None):
        if not salt:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(senha.encode()), salt
    
    @staticmethod
    def criptografar(entrada, saida, senha):
        with open(entrada, 'rb') as f:
            conteudo = f.read()
        
        chave, salt = ProtetorArquivosServidor.derivar_chave(senha)
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(chave), modes.GCM(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(conteudo) + enc.finalize()
        
        with open(saida, 'wb') as f:
            f.write(salt + iv + enc.tag + ct)
        print(f"[OK] Arquivo criptografado: {saida}")
    
    @staticmethod
    def descriptografar(entrada, saida, senha):
        with open(entrada, 'rb') as f:
            dados = f.read()
        
        salt = dados[:16]
        iv = dados[16:28]
        tag = dados[28:44]
        ct = dados[44:]
        
        chave, _ = ProtetorArquivosServidor.derivar_chave(senha, salt)
        cipher = Cipher(algorithms.AES(chave), modes.GCM(iv, tag), backend=default_backend())
        dec = cipher.decryptor()
        conteudo = dec.update(ct) + dec.finalize()
        
        with open(saida, 'wb') as f:
            f.write(conteudo)
        print(f"[OK] Arquivo descriptografado: {saida}")


def demonstracao():
    print("\n" + "="*80)
    print("SOLUCAO: PROTECAO DE INFORMACOES EM SISTEMA CORPORATIVO")
    print("="*80 + "\n")
    
    # Setup
    print("SETUP: Gerando pares de chaves")
    print("-" * 80)
    
    chave_priv_rh, chave_pub_rh = GerenciadorChaves.gerar_par_chaves_rsa()
    GerenciadorChaves.salvar_chave_privada(chave_priv_rh, 'chave_privada_rh.pem', 'senha_rh')
    GerenciadorChaves.salvar_chave_publica(chave_pub_rh, 'chave_publica_rh.pem')
    
    chave_priv_jur, chave_pub_jur = GerenciadorChaves.gerar_par_chaves_rsa()
    GerenciadorChaves.salvar_chave_privada(chave_priv_jur, 'chave_privada_juridico.pem', 'senha_juridico')
    GerenciadorChaves.salvar_chave_publica(chave_pub_jur, 'chave_publica_juridico.pem')
    
    print("\n[OK] Chaves geradas com sucesso")
    
    # Cenario 1 & 2
    print("\n\n" + "="*80)
    print("CENARIO 1 E 2: Envio Seguro com Autenticacao")
    print("="*80)
    
    gestor_rh = DocumentoSeguro("RH", chave_priv_rh, chave_pub_jur)
    
    conteudo = """CONTRATO DE TRABALHO
Data: 22/04/2026
Funcionario: Joao Silva
Cargo: Analista de Sistemas
Salario: R$ 5.000,00
Clauses especiais...
Documento sensivel que requer protecao."""
    
    envelope = gestor_rh.enviar(conteudo, "Contrato de Trabalho - Joao Silva")
    
    print("\n[OK] Documento preparado para transmissao")
    print(f"  Remetente: {envelope['remetente']}")
    print(f"  Titulo: {envelope['titulo']}")
    print(f"  Conteudo: [CIFRADO] {envelope['ciphertext'][:40]}...")
    
    print("\n>>> Enviando pela rede (documento protegido)")
    print("    Mesmo se interceptado, conteudo fica confidencial\n")
    
    resultado = DocumentoSeguro.receber(envelope, chave_priv_jur, chave_pub_rh)
    
    print("[OK] Documento recebido no Juridico\n")
    
    if resultado['sucesso']:
        print(f"  Status: {resultado['msg']}")
        print(f"  Remetente: {resultado['remetente']}")
        print(f"  Assinatura valida: {resultado['assinatura_valida']}")
        print(f"\n  Conteudo descriptografado:")
        print("  " + "-" * 76)
        for linha in resultado['conteudo'].split('\n'):
            print(f"  {linha}")
        print("  " + "-" * 76)
    
    # Cenario 3
    print("\n\n" + "="*80)
    print("CENARIO 3: Protecao de Arquivos Armazenados no Servidor")
    print("="*80)
    
    arquivo_original = "documento_estrategico.txt"
    with open(arquivo_original, 'w') as f:
        f.write("""PARECERES INTERNOS - MUITO CONFIDENCIAL
        
Data: 22/04/2026
Assunto: Avaliacao de Recursos Humanos

Parecer sobre o desempenho dos setores:
- RH: Excelente gestao, 95/100
- Juridico: Muito bom, 87/100
- Financeiro: Regular, 72/100

Informacoes altamente sensiveis.""")
    
    print(f"\n[OK] Arquivo original criado: {arquivo_original}")
    print(f"  Tamanho: {os.path.getsize(arquivo_original)} bytes")
    print(f"  Conteudo: legivel em texto plano\n")
    
    arquivo_cif = "documento_estrategico.enc"
    ProtetorArquivosServidor.criptografar(arquivo_original, arquivo_cif, "senha_servidor_2026")
    
    print(f"\n[OK] Arquivo criptografado: {arquivo_cif}")
    print(f"  Tamanho: {os.path.getsize(arquivo_cif)} bytes")
    print(f"  Conteudo: [ILEGIVEL]")
    
    print("\n  [OK] Mesmo com acesso ao disco, arquivo fica protegido")
    print("  [OK] Apenas quem conhece senha pode acessar\n")
    
    print(">>> Recuperando arquivo criptografado...\n")
    arquivo_rec = "documento_estrategico_recuperado.txt"
    ProtetorArquivosServidor.descriptografar(arquivo_cif, arquivo_rec, "senha_servidor_2026")
    
    print(f"\n[OK] Arquivo descriptografado: {arquivo_rec}")
    
    with open(arquivo_rec, 'r') as f:
        print(f"  Primeiras linhas:")
        for i, linha in enumerate(f):
            if i < 5:
                print(f"  {linha.rstrip()}")
    
    # Cenario 4
    print("\n\n" + "="*80)
    print("CENARIO 4: Troca Segura de Chaves sem Envio Manual")
    print("="*80)
    
    chave_priv_fin, chave_pub_fin = GerenciadorChaves.gerar_par_chaves_rsa()
    
    chave_sessao = CriptografiaSimetrica.gerar_chave()
    print(f"\n[OK] Chave de sessao gerada: {len(chave_sessao)} bytes")
    
    chave_encap = EncapsulamentoChaves.encapsular(chave_sessao, chave_pub_fin)
    print(f"[OK] Chave encapsulada com RSA-OAEP")
    print(f"  Tamanho cifrado: {len(chave_encap)} caracteres base64\n")
    
    print(">>> Enviando chave encapsulada pela rede")
    print("   Apenas quem tem chave privada pode decifrar\n")
    
    chave_recuperada = EncapsulamentoChaves.desencapsular(chave_encap, chave_priv_fin)
    
    print(f"[OK] Chave desencapsulada no Financeiro")
    print(f"  Chaves identicas: {chave_recuperada == chave_sessao}")
    print(f"\n  [OK] Chave compartilhada com seguranca sem envio manual")
    print(f"  [OK] Sem necessidade de email ou planilha")
    
    # Resumo
    print("\n\n" + "="*80)
    print("RESUMO DE SEGURANCA")
    print("="*80 + "\n")
    
    print("COMPONENTES UTILIZADOS:\n")
    
    print("1. CRIPTOGRAFIA SIMETRICA (AES-256-GCM)")
    print("   [OK] Protege conteudo em transito")
    print("   [OK] Rapida e eficiente")
    print("   [OK] Autenticacao integrada (modo GCM)")
    print("   [OK] Cenarios cobertos: 1, 3")
    
    print("\n2. CRIPTOGRAFIA ASSIMETRICA (RSA-2048)")
    print("   [OK] Encapsula chaves simetricas")
    print("   [OK] Cada setor tem seu par de chaves")
    print("   [OK] Chaves publicas compartilhaveis")
    print("   [OK] Cenarios cobertos: 4")
    
    print("\n3. ASSINATURA DIGITAL (RSA-PSS com SHA-256)")
    print("   [OK] Prova autoria do documento")
    print("   [OK] Detecta qualquer alteracao")
    print("   [OK] Nao repudiacao legal")
    print("   [OK] Cenarios cobertos: 2")
    
    print("\n4. DERIVACAO DE CHAVES (PBKDF2-SHA256)")
    print("   [OK] Converte senhas em chaves fortes")
    print("   [OK] Resistente a forca bruta")
    print("   [OK] Cenarios cobertos: 3")
    
    print("\n\nFLUXO SEGURO INTEGRADO:")
    print("-----------------------------------------------")
    print("Remetente (RH) -> Destinatario (Juridico)")
    print("\n1. RH gera chave simetrica aleatoria")
    print("2. RH cifra documento com AES-256")
    print("3. RH assina documento para prova de origem")
    print("4. RH encapsula chave AES com chave publica do Juridico")
    print("5. RH envia envelope protegido")
    print("\n6. Juridico recebe envelope")
    print("7. Juridico desencapsula com sua chave privada")
    print("8. Juridico decifra conteudo com chave simetrica")
    print("9. Juridico verifica assinatura (confirma autoria)")
    print("-----------------------------------------------")
    
    print("\n\nCONFORMIDADE COM REQUISITOS:")
    print("[OK] Protecao de conteudo em transito (Cenario 1)")
    print("[OK] Confirmacao de autoria e integridade (Cenario 2)")
    print("[OK] Protecao de arquivos armazenados (Cenario 3)")
    print("[OK] Troca segura sem envio manual de senhas (Cenario 4)")
    print("\n[OK] Sem necessidade de email ou planilha para chaves")
    print("[OK] Arquivos cifrados mesmo em caso de acesso ao disco")
    print("[OK] Assinatura tambem previne alteracoes em transito")
    
    # Limpeza
    print("\n\n" + "="*80)
    print("LIMPEZA DE ARQUIVOS DE TESTE")
    print("="*80)
    
    for arq in [arquivo_original, arquivo_cif, arquivo_rec]:
        if os.path.exists(arq):
            os.remove(arq)
            print(f"[OK] Removido: {arq}")
    
    print("\n[OK] Demonstracao concluida com sucesso!")


if __name__ == "__main__":
    demonstracao()
