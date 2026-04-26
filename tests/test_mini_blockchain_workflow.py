import tempfile
import unittest

from src.mini_blockchain.auth import login_user, register_user
from src.mini_blockchain.blockchain import add_block, run_tamper_demo, validate_chain
from src.mini_blockchain.crypto.alg_totp import totp_now
from src.mini_blockchain.storage import ensure_data_files, set_data_dir


class TestMiniBlockchainWorkflow(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        set_data_dir(self.tempdir.name)
        ensure_data_files()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_register_login_add_block_and_validate(self):
        out = register_user("alice", "senhaforte", kdf_name="pbkdf2")
        code = totp_now(out["totp_secret"])
        session = login_user("alice", "senhaforte", code)

        self.assertIsNotNone(session)
        block = add_block(session, "primeiro bloco de alice")
        self.assertEqual(block["owner"], "alice")

        status = validate_chain(user_keys={"alice": session.user_data_key})
        self.assertTrue(status["ok"])

    def test_isolation_between_users(self):
        a = register_user("alice", "senhaalice", kdf_name="pbkdf2")
        b = register_user("bob", "senhabob", kdf_name="scrypt")

        sa = login_user("alice", "senhaalice", totp_now(a["totp_secret"]))
        sb = login_user("bob", "senhabob", totp_now(b["totp_secret"]))

        self.assertIsNotNone(sa)
        self.assertIsNotNone(sb)

        add_block(sa, "dado de alice")
        add_block(sb, "dado de bob")

        # Com a chave errada, deve aparecer falha de autenticacao em algum bloco.
        result = validate_chain(user_keys={"alice": sb.user_data_key})
        self.assertFalse(result["ok"])
        self.assertTrue(any("AES-GCM" in err for err in result["errors"]))

    def test_tamper_demo_detects_problems(self):
        out = register_user("carol", "senhaccc", kdf_name="pbkdf2")
        sc = login_user("carol", "senhaccc", totp_now(out["totp_secret"]))

        add_block(sc, "bloco 1")
        add_block(sc, "bloco 2")

        demo = run_tamper_demo(user_keys={"carol": sc.user_data_key})
        self.assertTrue(demo["ran"])
        self.assertFalse(demo["tamper_ciphertext"]["ok"])
        self.assertFalse(demo["tamper_hash_prev"]["ok"])


if __name__ == "__main__":
    unittest.main()
