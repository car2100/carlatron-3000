from __future__ import annotations

from getpass import getpass

from src.mini_blockchain.auth import Session, login_user, register_user
from src.mini_blockchain.blockchain import (
    add_block,
    list_block_metadata,
    read_user_blocks,
    run_tamper_demo,
    validate_chain,
)
from src.mini_blockchain.storage import ensure_data_files


MENU = """
=== Mini-Blockchain (Seguranca de Redes) ===
1. Cadastrar usuario
2. Fazer login
3. Adicionar bloco
4. Listar blockchain
5. Ler meus blocos
6. Validar blockchain
7. Executar teste de manipulacao
8. Logout
9. Sair
"""


def _print_metadata() -> None:
    items = list_block_metadata()
    if not items:
        print("Blockchain vazia.")
        return

    for block in items:
        print(
            f"[#{block['index']}] owner={block['owner']} timestamp={block['timestamp']} "
            f"hash_prev={block['hash_prev']} block_hash={block['block_hash']}"
        )


def _register_flow() -> None:
    print("\n-- Cadastro --")
    username = input("Usuario: ").strip()
    password = getpass("Senha: ")
    kdf_raw = input("KDF (pbkdf2/scrypt) [pbkdf2]: ").strip().lower() or "pbkdf2"

    try:
        out = register_user(username=username, password=password, kdf_name=kdf_raw)
    except Exception as exc:
        print(f"Erro no cadastro: {exc}")
        return

    print("\nUsuario cadastrado com sucesso.")
    print("Configure seu app autenticador com este segredo TOTP:")
    print(f"TOTP Secret: {out['totp_secret']}")
    print(f"Provisioning URI: {out['provisioning_uri']}")


def _login_flow() -> Session | None:
    print("\n-- Login (senha + TOTP) --")
    username = input("Usuario: ").strip()
    password = getpass("Senha: ")
    code = input("Codigo TOTP: ").strip()

    session = login_user(username, password, code)
    if session is None:
        print("Falha no login. Verifique senha/TOTP.")
        return None

    print(f"Login OK. Bem-vindo, {session.username}.")
    return session


def _add_block_flow(session: Session | None) -> None:
    if session is None:
        print("Voce precisa fazer login primeiro.")
        return

    message = input("Mensagem do bloco: ").strip()
    try:
        block = add_block(session, message)
    except Exception as exc:
        print(f"Erro ao adicionar bloco: {exc}")
        return

    print(f"Bloco #{block['index']} adicionado para {session.username}.")


def _read_my_blocks_flow(session: Session | None) -> None:
    if session is None:
        print("Voce precisa fazer login para ler seus blocos.")
        return

    blocks = read_user_blocks(session)
    if not blocks:
        print("Voce ainda nao possui blocos.")
        return

    print(f"\n-- Blocos de {session.username} --")
    for block in blocks:
        print(f"[#{block['index']}] {block['timestamp']} -> {block['message']}")


def _validate_flow(session: Session | None) -> None:
    user_keys = None
    if session is not None:
        # Se houver sessao, validamos tambem autenticidade AES-GCM dos blocos do dono.
        user_keys = {session.username: session.user_data_key}

    result = validate_chain(user_keys=user_keys)
    if result["ok"]:
        print(f"Blockchain valida. Total de blocos: {result['total_blocks']}")
    else:
        print("Foram detectados problemas:")
        for err in result["errors"]:
            print(f"- {err}")


def _tamper_demo_flow(session: Session | None) -> None:
    if session is None:
        print("Faca login para executar o teste de manipulacao com verificacao AES-GCM.")
        return

    demo = run_tamper_demo(user_keys={session.username: session.user_data_key})
    if not demo.get("ran"):
        print(f"Teste nao executado: {demo.get('reason')}")
        return

    print("\nResultado tamper ciphertext:")
    print(demo.get("tamper_ciphertext"))

    print("\nResultado tamper hash_prev:")
    print(demo.get("tamper_hash_prev"))


def main() -> None:
    ensure_data_files()
    session: Session | None = None

    while True:
        print(MENU)
        option = input("Escolha uma opcao: ").strip()

        if option == "1":
            _register_flow()
        elif option == "2":
            session = _login_flow()
        elif option == "3":
            _add_block_flow(session)
        elif option == "4":
            _print_metadata()
        elif option == "5":
            _read_my_blocks_flow(session)
        elif option == "6":
            _validate_flow(session)
        elif option == "7":
            _tamper_demo_flow(session)
        elif option == "8":
            session = None
            print("Logout realizado.")
        elif option == "9":
            print("Encerrando.")
            break
        else:
            print("Opcao invalida.")


if __name__ == "__main__":
    main()
