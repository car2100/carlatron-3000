# Explicacao teorica (resumo)

## 1) TOTP (2FA)
TOTP e um codigo temporario gerado a partir de:
- segredo compartilhado (Base32), e
- tempo atual em janelas de 30 segundos.

No login, o servidor recalcula o codigo esperado e compara com o codigo digitado.
Assim, mesmo com a senha descoberta, o atacante ainda precisa do segundo fator.

## 2) Derivacao de chave (PBKDF2 / scrypt)
Senha nao deve ser usada diretamente como chave AES.
Por isso usamos KDF:
- entrada: senha + salt;
- saida: chave derivada.

O salt evita que duas senhas iguais gerem a mesma chave em usuarios diferentes.
PBKDF2 usa iteracoes; scrypt adiciona custo de memoria (memory-hard).

## 3) AES-GCM por bloco
Cada bloco guarda dados cifrados em AES-GCM.
AES-GCM oferece:
- confidencialidade (nao da para ler sem chave), e
- integridade/autenticidade (tag GCM detecta alteracao).

Cada cifragem usa nonce de 12 bytes aleatorio e unico.
Reutilizar nonce com mesma chave e inseguro em GCM.

## 4) Encadeamento hash_prev
Cada bloco aponta para o hash do bloco anterior (`hash_prev`).
Tambem calculamos `block_hash` com SHA-256 sobre campos canonicos do bloco.

Se alguem altera um bloco antigo, o hash muda e a cadeia fica inconsistente,
permitindo detectar adulteracao estrutural.

## 5) Isolamento entre usuarios
Cada usuario possui sua propria `user_data_key`.
Blocos de Alice sao cifrados com a chave de Alice, e blocos de Bob com a chave de Bob.
Assim, um usuario nao deve conseguir decifrar os blocos do outro.
