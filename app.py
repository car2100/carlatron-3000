# Mini-Blockchain — Segurança de Redes (UFSC)
# Tudo em um único arquivo para facilitar a leitura e apresentação.

import base64
import copy
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from getpass import getpass

import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ARQUIVO_USUARIOS = "data/users.json"
ARQUIVO_CADEIA   = "data/blockchain.json"


# =============================================================================
# UTILITÁRIOS
# =============================================================================

def b64e(dados: bytes) -> str:
    """Converte bytes para string Base64."""
    return base64.b64encode(dados).decode()

def b64d(texto: str) -> bytes:
    """Converte string Base64 para bytes."""
    return base64.b64decode(texto)

def agora_iso() -> str:
    """Retorna o instante atual no formato ISO 8601 UTC."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# =============================================================================
# DERIVAÇÃO DE CHAVE — PBKDF2
# =============================================================================

def derivar_chave(senha: str, salt: bytes) -> bytes:
    """
    PBKDF2-HMAC-SHA256: transforma senha em chave AES de 32 bytes.
    O salt garante que senhas iguais geram chaves diferentes.
    """
    return hashlib.pbkdf2_hmac("sha256", senha.encode(), salt, 300_000, dklen=32)


# =============================================================================
# CRIPTOGRAFIA AUTENTICADA — AES-GCM
# =============================================================================

def cifrar(chave: bytes, texto: bytes) -> dict:
    """
    Cifra com AES-GCM:
      - nonce de 12 bytes aleatório (único por operação)
      - ciphertext inclui a tag de autenticação no final
    Retorna {"nonce": ..., "ct": ...} em Base64.
    """
    nonce = secrets.token_bytes(12)
    ct = AESGCM(chave).encrypt(nonce, texto, None)
    return {"nonce": b64e(nonce), "ct": b64e(ct)}

def decifrar(chave: bytes, blob: dict) -> bytes:
    """
    Decifra AES-GCM e verifica a tag automaticamente.
    Se qualquer byte foi alterado, lança exceção (adulteração detectada).
    """
    nonce = b64d(blob["nonce"])
    ct    = b64d(blob["ct"])
    return AESGCM(chave).decrypt(nonce, ct, None)


# =============================================================================
# PERSISTÊNCIA
# =============================================================================

def carregar_usuarios() -> dict:
    try:
        with open(ARQUIVO_USUARIOS) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def salvar_usuarios(usuarios: dict):
    with open(ARQUIVO_USUARIOS, "w") as f:
        json.dump(usuarios, f, indent=2, ensure_ascii=False)

def carregar_cadeia() -> list:
    try:
        with open(ARQUIVO_CADEIA) as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def salvar_cadeia(cadeia: list):
    with open(ARQUIVO_CADEIA, "w") as f:
        json.dump(cadeia, f, indent=2, ensure_ascii=False)


# =============================================================================
# USUÁRIOS — CADASTRO E LOGIN
# =============================================================================

def cadastrar(nome: str, senha: str) -> str:
    """
    Fluxo de cadastro:
    1. Gera salt aleatório
    2. Deriva KEK (Key Encryption Key) da senha via PBKDF2
    3. Gera totp_secret e user_data_key aleatórios
    4. Cifra ambos com AES-GCM usando a KEK (nunca ficam em claro no disco)
    5. Salva no arquivo apenas: salt + bundle cifrado
    Retorna o totp_secret para o usuário configurar no app autenticador.
    """
    usuarios = carregar_usuarios()
    if nome in usuarios:
        raise ValueError("Usuário já existe.")

    salt = secrets.token_bytes(16)
    kek  = derivar_chave(senha, salt)

    totp_secret   = pyotp.random_base32()
    user_data_key = secrets.token_bytes(32)

    bundle = json.dumps({
        "totp":     totp_secret,
        "session_key": b64e(user_data_key),
    }).encode()

    bundle_cifrado = cifrar(kek, bundle)

    usuarios[nome] = {
        "salt":       b64e(salt),
        "bundle_nonce": bundle_cifrado["nonce"],
        "bundle_ct":    bundle_cifrado["ct"],
    }
    salvar_usuarios(usuarios)
    return totp_secret


def login(nome: str, senha: str, codigo_totp: str) -> dict | None:
    """
    Fluxo de login (2 fatores):
    1. Deriva a mesma KEK usando o salt salvo
    2. Tenta decifrar o bundle — se a senha for errada, a tag AES-GCM falha
    3. Verifica o código TOTP
    4. Gera a chave de sessão: recupera user_data_key do bundle (nunca fica em disco diretamente)
    Retorna sessão {usuario, session_key} ou None em caso de falha.
    """
    usuarios = carregar_usuarios()
    if nome not in usuarios:
        return None

    reg  = usuarios[nome]
    salt = b64d(reg["salt"])
    kek  = derivar_chave(senha, salt)

    try:
        plain  = decifrar(kek, {"nonce": reg["bundle_nonce"], "ct": reg["bundle_ct"]})
        bundle = json.loads(plain)
    except Exception:
        return None  # senha errada → autenticação AES-GCM falha

    if not pyotp.TOTP(bundle["totp"]).verify(codigo_totp, valid_window=1):
        return None  # TOTP inválido

    # Chave de sessão: recuperada do bundle cifrado no momento do login.
    # Fica apenas em memória durante a sessão, nunca em disco sem cifragem.
    session_key = b64d(bundle["session_key"])
    return {"usuario": nome, "session_key": session_key}


# =============================================================================
# BLOCKCHAIN
# =============================================================================

def calcular_hash_bloco(bloco: dict) -> str:
    """
    SHA-256 dos campos imutáveis do bloco.
    Qualquer alteração nestes campos muda o hash e quebra o encadeamento.
    """
    campos = json.dumps({
        "index":     bloco["index"],
        "owner":     bloco["owner"],
        "timestamp": bloco["timestamp"],
        "hash_prev": bloco["hash_prev"],
        "nonce":     bloco["nonce"],
        "ct":        bloco["ct"],
    }, sort_keys=True).encode()
    return hashlib.sha256(campos).hexdigest()


def adicionar_bloco(sessao: dict, mensagem: str):
    """
    Adiciona bloco cifrado do usuário na cadeia.
    A mensagem fica cifrada com AES-GCM usando a user_data_key do usuário.
    """
    cadeia    = carregar_cadeia()
    index     = len(cadeia)
    timestamp = agora_iso()
    hash_prev = "GENESIS" if index == 0 else cadeia[-1]["block_hash"]

    ct_blob = cifrar(sessao["session_key"], mensagem.encode())

    bloco = {
        "index":      index,
        "owner":      sessao["usuario"],
        "timestamp":  timestamp,
        "hash_prev":  hash_prev,
        "nonce":      ct_blob["nonce"],
        "ct":         ct_blob["ct"],
        "block_hash": "",
    }
    bloco["block_hash"] = calcular_hash_bloco(bloco)

    cadeia.append(bloco)
    salvar_cadeia(cadeia)
    print(f"Bloco #{index} adicionado.")


def listar_cadeia():
    """Exibe metadados públicos de todos os blocos (sem decifrar)."""
    cadeia = carregar_cadeia()
    if not cadeia:
        print("Blockchain vazia.")
        return
    for b in cadeia:
        print(f"  [#{b['index']}] owner={b['owner']}  {b['timestamp']}")
        print(f"         hash_prev={b['hash_prev'][:20]}...")
        print(f"         block_hash={b['block_hash'][:20]}...")


def ler_meus_blocos(sessao: dict):
    """Decifra e exibe apenas os blocos do usuário logado."""
    cadeia = carregar_cadeia()
    meus   = [b for b in cadeia if b["owner"] == sessao["usuario"]]
    if not meus:
        print("Você ainda não tem blocos.")
        return
    for b in meus:
        try:
            msg = decifrar(sessao["session_key"], {"nonce": b["nonce"], "ct": b["ct"]}).decode()
            print(f"  [#{b['index']}] {b['timestamp']} → {msg}")
        except Exception:
            print(f"  [#{b['index']}] *** FALHA DE AUTENTICAÇÃO — bloco adulterado ***")


def validar_cadeia():
    """
    Verifica a integridade de toda a cadeia:
    - hash_prev de cada bloco aponta para o block_hash do anterior
    - block_hash recalculado bate com o armazenado
    """
    cadeia = carregar_cadeia()
    if not cadeia:
        print("Blockchain vazia.")
        return
    erros = 0
    for i, b in enumerate(cadeia):
        prev_esperado = "GENESIS" if i == 0 else cadeia[i - 1]["block_hash"]
        if b["hash_prev"] != prev_esperado:
            print(f"  ERRO bloco #{i}: hash_prev inválido")
            erros += 1
        if b["block_hash"] != calcular_hash_bloco(b):
            print(f"  ERRO bloco #{i}: block_hash inválido")
            erros += 1
    if erros == 0:
        print(f"Cadeia válida! ({len(cadeia)} blocos, nenhum erro)")


def teste_adulteracao(sessao: dict):
    """
    Demonstração de adulteração:
    1. Altera 1 byte do ciphertext → AES-GCM detecta
    2. Altera hash_prev → encadeamento quebra
    A cadeia é restaurada ao final.
    """
    cadeia = carregar_cadeia()
    if not cadeia:
        print("Blockchain vazia.")
        return

    backup = copy.deepcopy(cadeia)
    ultimo = len(cadeia) - 1

    # --- Adultera ciphertext ---
    ct_bytes    = bytearray(b64d(cadeia[ultimo]["ct"]))
    ct_bytes[0] ^= 0xFF
    cadeia[ultimo]["ct"] = b64e(bytes(ct_bytes))
    salvar_cadeia(cadeia)

    print("\n[Teste 1] Após alterar 1 byte do ciphertext:")
    print("  → Tentando ler blocos:")
    ler_meus_blocos(sessao)
    print("  → Validando cadeia:")
    validar_cadeia()

    # --- Restaura e adultera hash_prev ---
    salvar_cadeia(copy.deepcopy(backup))
    cadeia = carregar_cadeia()
    if len(cadeia) >= 2:
        cadeia[1]["hash_prev"] = "ADULTERADO"
        salvar_cadeia(cadeia)
        print("\n[Teste 2] Após alterar hash_prev do bloco #1:")
        print("  → Validando cadeia:")
        validar_cadeia()

    # --- Restaura ---
    salvar_cadeia(backup)
    print("\nCadeia restaurada ao estado original.")


# =============================================================================
# MENU PRINCIPAL
# =============================================================================

MENU = """
=== Mini-Blockchain — Segurança de Redes (UFSC) ===
1. Cadastrar usuário
2. Fazer login
3. Adicionar bloco
4. Listar blockchain (metadados públicos)
5. Ler meus blocos (decifrado)
6. Validar blockchain
7. Teste de adulteração
8. Logout
9. Sair
"""

def main():
    os.makedirs("data", exist_ok=True)
    sessao = None

    while True:
        print(MENU)
        if sessao:
            print(f"  [Logado como: {sessao['usuario']}]")
        opcao = input("Opção: ").strip()

        if opcao == "1":
            nome  = input("Nome de usuário: ").strip()
            senha = getpass("Senha: ")
            try:
                totp = cadastrar(nome, senha)
                uri  = pyotp.TOTP(totp).provisioning_uri(nome, issuer_name="MiniBlockchain")
                print(f"\nCadastro OK!")
                print(f"  Segredo TOTP : {totp}")
                print(f"  URI para app : {uri}")
            except Exception as e:
                print(f"Erro: {e}")

        elif opcao == "2":
            nome   = input("Nome de usuário: ").strip()
            senha  = getpass("Senha: ")
            codigo = input("Código TOTP (6 dígitos): ").strip()
            sessao = login(nome, senha, codigo)
            if sessao:
                print(f"Login bem-sucedido! Bem-vindo, {nome}.")
            else:
                print("Falha no login. Verifique usuário, senha e TOTP.")

        elif opcao == "3":
            if not sessao:
                print("Faça login primeiro (opção 2).")
            else:
                msg = input("Mensagem do bloco: ").strip()
                if msg:
                    adicionar_bloco(sessao, msg)

        elif opcao == "4":
            listar_cadeia()

        elif opcao == "5":
            if not sessao:
                print("Faça login primeiro (opção 2).")
            else:
                ler_meus_blocos(sessao)

        elif opcao == "6":
            validar_cadeia()

        elif opcao == "7":
            if not sessao:
                print("Faça login primeiro (opção 2).")
            else:
                teste_adulteracao(sessao)

        elif opcao == "8":
            sessao = None
            print("Logout realizado.")

        elif opcao == "9":
            print("Encerrando.")
            break

        else:
            print("Opção inválida.")


if __name__ == "__main__":
    main()
