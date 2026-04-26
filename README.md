# Mini-Blockchain em Python (Seguranca de Redes)

Projeto academico com foco didatico para demonstrar, de forma simples e objetiva:
- autenticacao forte com senha + TOTP (2FA);
- derivacao de chave com PBKDF2 ou scrypt;
- criptografia autenticada com AES-GCM por bloco;
- encadeamento de blocos por `hash_prev` + `block_hash`;
- deteccao de adulteracao (tampering) em dados e estrutura da cadeia.

## Requisitos
- Python 3.10+
- Dependencias listadas em `requirements.txt`

## Instalacao e execucao
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

## Menu da aplicacao
Ao executar `app.py`, o menu oferece:
1. Cadastrar usuario
2. Fazer login
3. Adicionar bloco
4. Listar blockchain
5. Ler meus blocos
6. Validar blockchain
7. Executar teste de manipulacao
8. Logout
9. Sair

## Dados gerados
A aplicacao cria automaticamente a pasta `data/` com:
- `data/users.json`: cadastro de usuarios e bundle cifrado (TOTP secret + chave de dados do usuario);
- `data/blockchain.json`: cadeia de blocos cifrados.

## Executar testes
Use descoberta de testes na pasta `tests`:
```bash
python3 -m unittest discover -s tests -v
```

## Roteiro rapido de demonstracao
1. Cadastrar `alice` e anotar `TOTP Secret`.
2. Configurar o segredo em um app autenticador (Google Authenticator, Aegis, etc.).
3. Fazer login com senha + codigo TOTP.
4. Adicionar 1 ou 2 blocos.
5. Listar a blockchain e ler os blocos da usuaria logada.
6. Rodar "Executar teste de manipulacao" e mostrar as falhas detectadas.

## Estrutura do projeto
- `app.py`: interface de linha de comando para demonstracao.
- `src/mini_blockchain/auth.py`: cadastro/login e recuperacao segura de segredos do usuario.
- `src/mini_blockchain/blockchain.py`: criacao, leitura, validacao e tamper test da cadeia.
- `src/mini_blockchain/storage.py`: persistencia em JSON.
- `src/mini_blockchain/crypto/`: modulos criptograficos separados (`alg_kdf`, `alg_totp`, `alg_aes_gcm`, `alg_hash`).
- `tests/`: testes unitarios de algoritmos e de fluxo completo.
- `docs/`: material teorico e validacao do mapeamento.

## Observacoes de seguranca (escopo didatico)
- Nenhuma senha e salva em claro.
- O `salt` do KDF e armazenado em claro (pratica correta).
- Segredos sensiveis do usuario ficam em bundle cifrado por AES-GCM.
- Cada cifragem usa nonce aleatorio de 12 bytes.
- Este projeto foi simplificado para fins academicos de apresentacao.
