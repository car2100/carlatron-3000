import json
import unittest

from src.mini_blockchain.blockchain_helpers import demo_user_bundle, make_block_hash
from src.mini_blockchain.crypto.alg_aes_gcm import aes_gcm_decrypt, aes_gcm_encrypt
from src.mini_blockchain.crypto.alg_crypto_common import CryptoError, b64d
from src.mini_blockchain.crypto.alg_hash import hmac_sha256_hex, sha256_hex, sha512_hex
from src.mini_blockchain.crypto.alg_kdf import derive_key_pbkdf2, derive_key_scrypt
from src.mini_blockchain.crypto.alg_totp import generate_totp_secret, totp_now, verify_totp


class TestAlgoritmosPython(unittest.TestCase):
    def test_pbkdf2_same_inputs_same_key(self):
        salt = bytes.fromhex("00112233445566778899aabbccddeeff")
        k1 = derive_key_pbkdf2("senha", salt, iterations=1000, length=32, hash_name="sha512")
        k2 = derive_key_pbkdf2("senha", salt, iterations=1000, length=32, hash_name="sha512")
        self.assertEqual(k1, k2)

    def test_pbkdf2_different_salt_different_key(self):
        k1 = derive_key_pbkdf2("senha", bytes.fromhex("00" * 16), iterations=1000, length=32)
        k2 = derive_key_pbkdf2("senha", bytes.fromhex("11" * 16), iterations=1000, length=32)
        self.assertNotEqual(k1, k2)

    def test_scrypt_same_inputs_same_key(self):
        salt = bytes.fromhex("53efb4b1157fccdb9902676329debc52")
        k1 = derive_key_scrypt("senha", salt, n=2048, r=8, p=1, length=32)
        k2 = derive_key_scrypt("senha", salt, n=2048, r=8, p=1, length=32)
        self.assertEqual(k1, k2)

    def test_aes_gcm_roundtrip_and_tamper_detection(self):
        key = bytes.fromhex("00" * 32)
        plaintext = b"mensagem confidencial"
        aad = b"owner=alice,index=1"

        blob = aes_gcm_encrypt(key, plaintext, aad)
        out = aes_gcm_decrypt(key, blob.nonce_b64, blob.ciphertext_b64, aad)
        self.assertEqual(out, plaintext)

        # Tamper em 1 byte do ciphertext para forcar falha de autenticacao
        tampered = bytearray(b64d(blob.ciphertext_b64))
        tampered[0] ^= 0x01

        with self.assertRaises(CryptoError):
            aes_gcm_decrypt(key, blob.nonce_b64, __import__("base64").b64encode(tampered).decode("ascii"), aad)

    def test_totp_now_verifies(self):
        secret = generate_totp_secret()
        code = totp_now(secret)
        self.assertTrue(verify_totp(secret, code, valid_window=1))

    def test_hashes_and_hmac_known_values(self):
        self.assertEqual(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        self.assertEqual(
            sha512_hex(b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        )
        self.assertEqual(
            hmac_sha256_hex(b"key", b"The quick brown fox jumps over the lazy dog"),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
        )

    def test_block_hash_deterministic(self):
        h1 = make_block_hash(1, "alice", "2026-04-24T22:10:00Z", "GENESIS", "abc", "def")
        h2 = make_block_hash(1, "alice", "2026-04-24T22:10:00Z", "GENESIS", "abc", "def")
        self.assertEqual(h1, h2)

    def test_demo_user_bundle_can_be_decrypted(self):
        password = "senhaforte"
        rec = demo_user_bundle(password)

        salt = b64d(rec["salt_b64"])
        kek = derive_key_pbkdf2(password, salt, iterations=300_000, length=32, hash_name="sha256")
        plain = aes_gcm_decrypt(kek, rec["bundle_nonce_b64"], rec["bundle_ciphertext_b64"])
        bundle = json.loads(plain.decode("utf-8"))

        self.assertIn("totp_secret", bundle)
        self.assertIn("user_data_key_b64", bundle)


if __name__ == "__main__":
    unittest.main()
