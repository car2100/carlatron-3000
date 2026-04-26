# Plano para o agente — Tarefa Prática de Implementação (Mini-Blockchain em Python)

## 1. Objetivo deste plano
Este documento traduz as diretrizes do trabalho em um plano técnico e de execução para o agente implementar a solução em **Python**, com foco em:

- aderência ao enunciado;
- escolhas criptográficas seguras;
- separação clara entre autenticação, derivação de chaves, criptografia dos blocos e persistência;
- geração de código apresentável, explicável e fácil de demonstrar.

---

## 2. Validação do enunciado

### 2.1 O que o trabalho exige
A tarefa pede uma **mini-blockchain multiusuário** em que cada usuário registra dados de forma segura, com:

- **AES-GCM** para confidencialidade e integridade dos dados;
- **senha + TOTP** para autenticação forte;
- **encadeamento por `hash_prev`** para integridade da cadeia;
- **isolamento por usuário**, de modo que cada um só consiga decifrar seus próprios dados;
- **KDF com PBKDF2 ou scrypt**;
- menu simples em modo texto;
- testes de login, leitura, integridade e KDF;
- documentação explicando TOTP, derivação de chave e encadeamento dos blocos. fileciteturn4file0

### 2.2 Restrições importantes do enunciado
O trabalho também impõe restrições explícitas:

- não usar chave/IV em variáveis globais ou de ambiente no momento da decifragem;
- usar **PBKDF2 ou scrypt**;
- usar **criptografia autenticada**;
- não usar **chaves e IVs fixos hardcoded**;
- se parâmetros forem armazenados, eles devem ficar em **arquivo cifrado**, exceto o **salt**, que pode ficar sem cifragem. fileciteturn4file10

### 2.3 Ponto de atenção técnico
Há uma ambiguidade no item que diz que **chaves/IVs devem ser gerados com PBKDF2 ou scrypt**. Tecnicamente:

- **KDF** é apropriado para **chaves**;
- para **AES-GCM**, o mais correto é usar **nonce/IV único e aleatório**, preferencialmente 96 bits.

Como o próprio enunciado também exige **“iv único para AES-GCM”**, o plano abaixo adota a interpretação tecnicamente mais segura:

- **PBKDF2/scrypt para derivar chaves**;
- **nonce/IV aleatório e único por bloco** usando CSPRNG.

Se o professor exigir literalmente “KDF também para IV”, isso deve ser confirmado antes da implementação final.

---

## 3. Base teórica mínima que sustenta a implementação

### 3.1 TOTP
Os slides indicam que **TOTP** usa uma **chave secreta compartilhada** e o **tempo atual dividido em janelas de 30 segundos**; se o tempo da geração e o da verificação não coincidirem, o código não bate. fileciteturn4file1 fileciteturn4file17

### 3.2 Criptografia autenticada
Os materiais destacam que, quando é necessário garantir **confidencialidade + integridade**, deve-se usar **criptografia autenticada**; os slides citam **GCM** como um dos padrões AEAD. fileciteturn4file2 fileciteturn4file18

### 3.3 PBKDF2 e scrypt
Os slides e materiais mostram que:

- **PBKDF2** deriva chave a partir de **password + salt + iterações**;
- o **salt deve ser aleatório**;
- **scrypt** aumenta custo de ataque por ser **memory-hard**. fileciteturn4file16 fileciteturn4file11 fileciteturn4file3

### 3.4 AES-GCM e integridade
O material Java mostra que no **AES/GCM** a falha de integridade aparece como erro de tag (`AEADBadTagException` / falha de MAC), então qualquer alteração indevida em ciphertext, tag ou AAD deve ser tratada como corrupção/tampering. fileciteturn4file9

### 3.5 Nonce/IV em GCM
O material também destaca que em GCM o **nonce é parâmetro do modo** e o tamanho recomendado é **12 octets (96 bits)**. fileciteturn4file7

---

## 4. Situação atual dos arquivos enviados
Eu consegui validar os PDFs do enunciado e dos materiais de apoio, mas **o arquivo `exemplosFIPS2.zip` não está entre os arquivos enviados nesta conversa**, então **não foi possível extraí-lo nem mapear os projetos NetBeans reais neste momento**. O enunciado menciona esse `.zip` no Moodle como base opcional em Java. fileciteturn4file0

### Impacto disso
O plano abaixo já prepara o agente para implementar a solução em Python sem depender do zip.

### Quando o zip for enviado
Assim que o `exemplosFIPS2.zip` for anexado, o agente deve:

1. extrair o zip;
2. identificar os projetos NetBeans;
3. localizar apenas os exemplos úteis para:
   - PBKDF2;
   - scrypt;
   - AES-GCM;
   - HMAC/TOTP;
   - hashing/encadeamento;
4. converter esses exemplos para Python;
5. reaproveitar só a lógica necessária, sem copiar estrutura desnecessária.

---

## 5. Decisões de arquitetura recomendadas

### 5.1 Linguagem e bibliotecas Python
Usar:

- `cryptography` para **AES-GCM**;
- `hashlib` para **SHA-256** e opcionalmente **pbkdf2_hmac** / `scrypt`;
- `pyotp` para **TOTP**;
- `secrets` para aleatoriedade criptográfica;
- `json` para serialização;
- `base64` para persistir bytes em JSON;
- `getpass` para entrada de senha no terminal.

### 5.2 Estratégia criptográfica
Adotar duas camadas conceituais:

#### Camada A — autenticação e recuperação de segredos do usuário
- No cadastro, gerar:
  - `salt_password` aleatório;
  - `totp_secret` aleatório;
  - `user_data_key` aleatória (DEK do usuário).
- Derivar uma **KEK** da senha com **PBKDF2-SHA256** ou **scrypt**.
- Proteger em AES-GCM um **bundle do usuário** contendo pelo menos:
  - `totp_secret`;
  - `user_data_key`.
- Persistir apenas:
  - `salt_password` em claro;
  - `bundle_nonce`;
  - `bundle_ciphertext`.

#### Camada B — cifragem dos blocos
- Cada bloco do usuário será cifrado com `user_data_key` usando **AES-GCM**.
- Cada bloco terá **nonce único**.
- O dado em claro do bloco nunca será persistido.

### 5.3 Sessão
Após login com senha + TOTP:

- recuperar `user_data_key` decifrando o bundle do usuário;
- gerar uma **chave de sessão em memória** apenas para o runtime, se desejar cumprir o item “após login, o sistema gera uma chave de sessão segura”;
- essa chave de sessão pode ser usada para proteger operações em memória, mas a cifra persistente dos blocos deve continuar associada ao usuário de forma reprodutível.

### 5.4 Encadeamento da blockchain
Cada bloco deve conter pelo menos:

- `index`;
- `owner`;
- `timestamp`;
- `hash_prev`;
- `nonce` do AES-GCM;
- `ciphertext`;
- `aad` opcional;
- `block_hash`.

### 5.5 Cálculo do hash do bloco
Calcular `block_hash = SHA-256(...)` sobre uma representação canônica do bloco, por exemplo:

- `index`
- `owner`
- `timestamp`
- `hash_prev`
- `nonce`
- `ciphertext`

**Não** incluir campos mutáveis ou derivados fora do formato canônico.

---

## 6. Estrutura de projeto recomendada

```text
mini_blockchain/
├─ app.py
├─ requirements.txt
├─ README.md
├─ docs/
│  └─ explicacao_teorica.md
├─ data/
│  ├─ users.json
│  └─ blockchain.json
├─ src/
│  ├─ config.py
│  ├─ models.py
│  ├─ storage.py
│  ├─ crypto_utils.py
│  ├─ auth.py
│  ├─ blockchain.py
│  ├─ menu.py
│  └─ tests_manual.py
└─ tests/
   ├─ test_auth.py
   ├─ test_crypto.py
   └─ test_blockchain.py
```

---

## 7. Modelo de dados sugerido

### 7.1 Usuários (`users.json`)
```json
{
  "alice": {
    "kdf": "pbkdf2",
    "kdf_params": {
      "iterations": 300000,
      "hash": "sha256"
    },
    "salt_password_b64": "...",
    "bundle_nonce_b64": "...",
    "bundle_ciphertext_b64": "..."
  }
}
```

### 7.2 Bundle do usuário (conteúdo decifrado internamente)
```json
{
  "totp_secret": "BASE32...",
  "user_data_key_b64": "..."
}
```

### 7.3 Blockchain (`blockchain.json`)
```json
[
  {
    "index": 0,
    "owner": "alice",
    "timestamp": "2026-04-24T22:10:00Z",
    "hash_prev": "GENESIS",
    "nonce_b64": "...",
    "ciphertext_b64": "...",
    "aad": {
      "owner": "alice",
      "index": 0,
      "timestamp": "2026-04-24T22:10:00Z"
    },
    "block_hash": "..."
  }
]
```

---

## 8. Regras de implementação para o agente

### 8.1 Cadastro
Implementar fluxo:

1. pedir `username`;
2. pedir senha;
3. gerar `salt_password`;
4. derivar KEK com PBKDF2 ou scrypt;
5. gerar `totp_secret`;
6. gerar `user_data_key` aleatória de 32 bytes;
7. montar bundle do usuário;
8. cifrar bundle com AES-GCM usando a KEK;
9. salvar registro do usuário;
10. mostrar ao usuário a secret do TOTP e, se quiser, uma URL provisioning para Authenticator.

### 8.2 Login
Implementar fluxo:

1. localizar usuário;
2. pedir senha;
3. derivar KEK usando o `salt_password` salvo;
4. tentar decifrar o bundle;
5. se falhar, login inválido;
6. pedir TOTP;
7. validar TOTP;
8. se válido, abrir sessão autenticada.

### 8.3 Adição de bloco
Implementar fluxo:

1. exigir sessão autenticada;
2. receber texto livre do bloco;
3. obter último bloco da cadeia;
4. definir `hash_prev`;
5. gerar `nonce` único de 12 bytes;
6. definir AAD opcional com `owner/index/timestamp`;
7. cifrar payload com AES-GCM e `user_data_key`;
8. calcular `block_hash`;
9. persistir bloco.

### 8.4 Leitura da blockchain
Implementar fluxo:

1. listar todos os blocos com metadados públicos;
2. ao tentar abrir um bloco:
   - se `owner != usuário logado`, mostrar apenas metadados;
   - se for do dono, tentar decifrar;
3. validar:
   - `hash_prev`;
   - `block_hash` recalculado;
   - tag do AES-GCM.

### 8.5 Validação da cadeia
Criar função que percorra toda a blockchain e retorne:

- blocos válidos;
- blocos com `hash_prev` inválido;
- blocos com `block_hash` inválido;
- blocos com falha de autenticação AES-GCM.

### 8.6 Teste de manipulação
Criar função de laboratório para:

- alterar 1 byte do `ciphertext`;
- alterar `hash_prev`;
- revalidar a cadeia;
- demonstrar falha esperada.

---

## 9. Escolhas concretas recomendadas

### 9.1 KDF
Preferência prática para este trabalho:

- **PBKDF2-HMAC-SHA256** com alto número de iterações, pela simplicidade e por estar alinhado ao material;
- ou **scrypt** se o grupo quiser mostrar maior robustez contra ataque offline.

### 9.2 Recomendação objetiva
Para reduzir risco de bugs e facilitar apresentação:

- usar **PBKDF2-HMAC-SHA256** no núcleo obrigatório;
- implementar **scrypt** como opção configurável ou demonstrativa extra.

### 9.3 AES-GCM
Usar:

- chave de 256 bits;
- nonce de 96 bits;
- AAD com metadados públicos do bloco.

### 9.4 Hash da cadeia
Usar **SHA-256**.

### 9.5 Persistência
Usar JSON para simplicidade, com bytes em Base64.

---

## 10. Mapeamento Java → Python que o agente deve seguir

Mesmo sem o zip, o mapeamento esperado é este:

### 10.1 PBKDF2
**Java / Bouncy Castle / JCE**
- `SecretKeyFactory.getInstance(...)`
- `PBEKeySpec` / equivalente

**Python**
- `hashlib.pbkdf2_hmac(...)`
- ou `cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC`

### 10.2 scrypt
**Java**
- `SecretKeyFactory.getInstance("SCRYPT", "BC")` / `ScryptKeySpec` fileciteturn4file3

**Python**
- `hashlib.scrypt(...)`
- ou `cryptography.hazmat.primitives.kdf.scrypt.Scrypt`

### 10.3 AES-GCM
**Java**
- `Cipher.getInstance("AES/GCM/NoPadding", "BC")` com `GCMParameterSpec` fileciteturn2file0 fileciteturn4file7

**Python**
- `cryptography.hazmat.primitives.ciphers.aead.AESGCM`

### 10.4 TOTP
**Java**
- bibliotecas que encapsulam RFC 6238

**Python**
- `pyotp.TOTP(secret).verify(code)`
- ou implementação manual com `hmac` + `hashlib` se o grupo quiser explicar o algoritmo

### 10.5 Hash do bloco
**Java**
- `MessageDigest.getInstance("SHA-256")`

**Python**
- `hashlib.sha256(...)`

---

## 11. Menu obrigatório sugerido

```text
1. Cadastrar usuário
2. Fazer login
3. Adicionar bloco
4. Listar blockchain
5. Ler meus blocos
6. Validar blockchain
7. Executar teste de manipulação
8. Logout
9. Sair
```

---

## 12. Casos de teste que o agente deve implementar

### 12.1 Autenticação
- senha correta + TOTP válido = sucesso;
- senha correta + TOTP inválido = falha;
- senha incorreta = falha. fileciteturn4file10

### 12.2 Multiusuário
- usuário A cria bloco e lê seu bloco;
- usuário B cria bloco e lê seu bloco;
- A não consegue decifrar bloco de B;
- B não consegue decifrar bloco de A. fileciteturn4file10

### 12.3 Integridade
- alterar ciphertext gera falha de autenticação AES-GCM;
- alterar `hash_prev` gera falha de validação da cadeia. fileciteturn4file10

### 12.4 KDF
- mesma senha + mesmo salt = mesma chave;
- mesma senha + salt diferente = chave diferente. fileciteturn4file10

---

## 13. Requisitos de qualidade do código
O agente deve gerar código com:

- tipagem quando fizer sentido;
- funções pequenas e bem nomeadas;
- comentários apenas onde ajudam a explicar a lógica criptográfica;
- tratamento explícito de exceções de cifra/autenticação;
- nenhuma chave hardcoded;
- nenhum IV fixo;
- nenhuma dependência de variável de ambiente para decifrar dados persistidos.

---

## 14. Itens que devem aparecer no README

O `README.md` deve conter:

1. objetivo do projeto;
2. requisitos de instalação;
3. criação de ambiente virtual;
4. instalação de dependências;
5. comando para executar a aplicação;
6. fluxo de demonstração;
7. explicação curta da arquitetura;
8. observação de que o projeto é acadêmico.

---

## 15. Itens que devem aparecer na documentação teórica
A documentação deve explicar, em linguagem simples:

### 15.1 TOTP
- o que é;
- papel da chave secreta;
- janela de 30 segundos;
- por que ele funciona como 2FA. fileciteturn4file1

### 15.2 Derivação de chave
- por que senha não deve ser usada diretamente como chave;
- papel do salt;
- papel das iterações / custo;
- diferença entre PBKDF2 e scrypt. fileciteturn4file16 fileciteturn4file11

### 15.3 Criptografia por bloco
- uso de AES-GCM;
- nonce único por bloco;
- confidencialidade + integridade. fileciteturn4file2 fileciteturn4file7

### 15.4 Encadeamento da blockchain
- `hash_prev`;
- imutabilidade lógica;
- detecção de adulteração.

---

## 16. Estratégia de apresentação
Na apresentação, a equipe deve mostrar esta sequência:

1. cadastro de dois usuários;
2. configuração do TOTP em app autenticador;
3. login bem-sucedido;
4. tentativa de login com TOTP inválido;
5. criação de blocos por usuários diferentes;
6. leitura isolada por usuário;
7. teste de manipulação do ciphertext;
8. teste de alteração de `hash_prev`;
9. explicação do código por módulos.

---

## 17. Definição de pronto
O trabalho só está pronto quando houver:

- aplicação CLI funcional;
- cadastro/login com senha + TOTP;
- blocos cifrados com AES-GCM;
- encadeamento por `hash_prev`;
- isolamento entre usuários;
- validação da cadeia;
- testes de manipulação;
- README de execução;
- documento teórico;
- código limpo o suficiente para apresentação.

---

## 18. Instruções finais para o agente

### 18.1 O que fazer primeiro
1. criar esqueleto do projeto;
2. implementar utilitários criptográficos;
3. implementar cadastro/login;
4. implementar blockchain;
5. implementar menu;
6. implementar testes e documentação.

### 18.2 O que evitar
- não usar ECB;
- não usar MD5 ou SHA-1;
- não armazenar senha em claro;
- não persistir segredo TOTP em claro;
- não usar nonce reaproveitado em GCM;
- não misturar lógica de menu com lógica criptográfica;
- não depender do zip Java para concluir a primeira versão.

### 18.3 Se o zip Java for enviado depois
O agente deve fazer uma segunda iteração para:

- extrair o zip;
- catalogar os exemplos relevantes;
- portar para Python apenas o que for útil;
- manter a arquitetura já definida neste plano.

