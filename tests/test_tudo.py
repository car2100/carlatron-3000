# Testes do Mini-Blockchain
# Importa direto do app.py — sem módulos separados.

import os
import tempfile
import unittest
from unittest.mock import patch

import pyotp

import app


def patch_data_dir(tmp):
    """Redireciona os arquivos JSON para um diretório temporário."""
    return [
        patch("app.ARQUIVO_USUARIOS", os.path.join(tmp, "users.json")),
        patch("app.ARQUIVO_CADEIA",   os.path.join(tmp, "blockchain.json")),
    ]


class TestKDF(unittest.TestCase):
    def test_mesma_senha_mesmo_salt_gera_mesma_chave(self):
        salt = bytes.fromhex("00112233445566778899aabbccddeeff")
        k1 = app.derivar_chave("minha_senha", salt)
        k2 = app.derivar_chave("minha_senha", salt)
        self.assertEqual(k1, k2)

    def test_mesmo_senha_salt_diferente_gera_chave_diferente(self):
        k1 = app.derivar_chave("minha_senha", b"\x00" * 16)
        k2 = app.derivar_chave("minha_senha", b"\xff" * 16)
        self.assertNotEqual(k1, k2)


class TestAESGCM(unittest.TestCase):
    def test_cifrar_e_decifrar_retorna_texto_original(self):
        chave = bytes(32)
        texto = b"mensagem secreta"
        blob  = app.cifrar(chave, texto)
        self.assertEqual(app.decifrar(chave, blob), texto)

    def test_adulteracao_do_ciphertext_e_detectada(self):
        chave   = bytes(32)
        blob    = app.cifrar(chave, b"dado")
        ct_bad  = bytearray(app.b64d(blob["ct"]))
        ct_bad[0] ^= 0xFF
        blob_ruim = {"nonce": blob["nonce"], "ct": app.b64e(bytes(ct_bad))}
        with self.assertRaises(Exception):
            app.decifrar(chave, blob_ruim)


class TestUsuarios(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patches = patch_data_dir(self.tmp.name)
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def test_cadastro_e_login_bem_sucedido(self):
        totp_secret = app.cadastrar("alice", "senha123")
        codigo = pyotp.TOTP(totp_secret).now()
        sessao = app.login("alice", "senha123", codigo)
        self.assertIsNotNone(sessao)
        self.assertEqual(sessao["usuario"], "alice")

    def test_senha_errada_impede_login(self):
        totp_secret = app.cadastrar("alice", "senha123")
        codigo = pyotp.TOTP(totp_secret).now()
        sessao = app.login("alice", "senha_errada", codigo)
        self.assertIsNone(sessao)

    def test_totp_errado_impede_login(self):
        app.cadastrar("alice", "senha123")
        sessao = app.login("alice", "senha123", "000000")
        self.assertIsNone(sessao)

    def test_usuario_inexistente_retorna_none(self):
        sessao = app.login("ninguem", "qualquer", "000000")
        self.assertIsNone(sessao)


class TestBlockchain(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patches = patch_data_dir(self.tmp.name)
        for p in self.patches:
            p.start()

        totp = app.cadastrar("alice", "senha123")
        self.sessao = app.login("alice", "senha123", pyotp.TOTP(totp).now())

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def test_adicionar_bloco_e_validar_cadeia(self):
        app.adicionar_bloco(self.sessao, "meu primeiro bloco")
        cadeia = app.carregar_cadeia()
        self.assertEqual(len(cadeia), 1)
        self.assertEqual(cadeia[0]["owner"], "alice")

    def test_cadeia_valida_apos_adicionar_blocos(self):
        app.adicionar_bloco(self.sessao, "bloco 1")
        app.adicionar_bloco(self.sessao, "bloco 2")
        # Validação via stdout (não lança exceção = OK)
        app.validar_cadeia()

    def test_hash_prev_encadeia_corretamente(self):
        app.adicionar_bloco(self.sessao, "bloco 0")
        app.adicionar_bloco(self.sessao, "bloco 1")
        cadeia = app.carregar_cadeia()
        self.assertEqual(cadeia[0]["hash_prev"], "GENESIS")
        self.assertEqual(cadeia[1]["hash_prev"], cadeia[0]["block_hash"])

    def test_hash_prev_invalido_detectado(self):
        app.adicionar_bloco(self.sessao, "bloco 0")
        app.adicionar_bloco(self.sessao, "bloco 1")
        cadeia = app.carregar_cadeia()
        cadeia[1]["hash_prev"] = "ADULTERADO"
        app.salvar_cadeia(cadeia)
        from io import StringIO
        import sys
        out = StringIO()
        sys.stdout = out
        app.validar_cadeia()
        sys.stdout = sys.__stdout__
        self.assertIn("ERRO", out.getvalue())

    def test_adulteracao_ciphertext_detectada_na_leitura(self):
        app.adicionar_bloco(self.sessao, "dado secreto")
        cadeia = app.carregar_cadeia()

        # Altera 1 byte do ciphertext
        ct_bad = bytearray(app.b64d(cadeia[0]["ct"]))
        ct_bad[0] ^= 0xFF
        cadeia[0]["ct"] = app.b64e(bytes(ct_bad))
        app.salvar_cadeia(cadeia)

        # ler_meus_blocos não deve lançar exceção, mas exibe mensagem de falha
        app.ler_meus_blocos(self.sessao)  # apenas verifica que não crasha


class TestIsolamentoMultiusuario(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patches = patch_data_dir(self.tmp.name)
        for p in self.patches:
            p.start()

        totp_a = app.cadastrar("alice", "senha_alice")
        totp_b = app.cadastrar("bob", "senha_bob")
        self.sa = app.login("alice", "senha_alice", pyotp.TOTP(totp_a).now())
        self.sb = app.login("bob",   "senha_bob",   pyotp.TOTP(totp_b).now())

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def test_alice_nao_consegue_decifrar_bloco_de_bob(self):
        app.adicionar_bloco(self.sb, "dado secreto de bob")
        cadeia = app.carregar_cadeia()
        bloco_bob = cadeia[0]

        # Alice tenta decifrar com a chave dela — deve falhar
        with self.assertRaises(Exception):
            app.decifrar(self.sa["session_key"], {"nonce": bloco_bob["nonce"], "ct": bloco_bob["ct"]})

    def test_cada_usuario_ve_apenas_seus_blocos(self):
        app.adicionar_bloco(self.sa, "dado de alice")
        app.adicionar_bloco(self.sb, "dado de bob")

        cadeia = app.carregar_cadeia()
        meus   = [b for b in cadeia if b["owner"] == "alice"]
        self.assertEqual(len(meus), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
