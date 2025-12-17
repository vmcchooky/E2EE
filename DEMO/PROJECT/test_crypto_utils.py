import os
import unittest
import tempfile

from cryptography.hazmat.primitives.asymmetric import rsa

import crypto_utils as cu


class TestCryptoUtils(unittest.TestCase):
    def test_generate_aes_key_length(self):
        key = cu.generate_aes_key()
        self.assertIsInstance(key, (bytes, bytearray))
        self.assertEqual(len(key), 32)  # 256-bit

    def test_aes_gcm_roundtrip(self):
        key = cu.generate_aes_key()
        pt = b"hello e2ee aes-gcm"
        ct = cu.aes_encrypt(pt, key)
        self.assertIsNotNone(ct)
        dec = cu.aes_decrypt(ct, key)
        self.assertEqual(dec, pt)

    def test_aes_gcm_tamper_returns_none(self):
        key = cu.generate_aes_key()
        pt = b"tamper test"
        ct = cu.aes_encrypt(pt, key)
        self.assertIsNotNone(ct)

        tampered = bytearray(ct)
        tampered[-1] ^= 0x01  # flip 1 bit
        dec = cu.aes_decrypt(bytes(tampered), key)
        self.assertIsNone(dec)

    def test_rsa_roundtrip(self):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = priv.public_key()

        msg = b"rsa oaep sha256"
        enc = cu.rsa_encrypt(msg, pub)
        dec = cu.rsa_decrypt(enc, priv)
        self.assertEqual(dec, msg)

    def test_public_key_fingerprint_stable(self):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = priv.public_key()
        pub_bytes = pub.public_bytes(
            encoding=cu.serialization.Encoding.PEM,
            format=cu.serialization.PublicFormat.SubjectPublicKeyInfo
        )
        fp1 = cu.public_key_fingerprint(pub_bytes, length=16)
        fp2 = cu.public_key_fingerprint(pub_bytes, length=16)
        self.assertEqual(fp1, fp2)
        self.assertEqual(len(fp1), 16)

    def test_generate_or_load_keys_create_then_load(self):
        with tempfile.TemporaryDirectory() as td:
            old_cwd = os.getcwd()
            try:
                os.chdir(td)

                name = "Alice"
                pwd = "strong_password_123"

                # create
                priv1, pub_bytes1 = cu.generate_or_load_keys(name, pwd)
                self.assertIsNotNone(priv1)
                self.assertIsNotNone(pub_bytes1)

                # load again with correct password
                priv2, pub_bytes2 = cu.generate_or_load_keys(name, pwd)
                self.assertIsNotNone(priv2)
                self.assertIsNotNone(pub_bytes2)
                self.assertEqual(pub_bytes1, pub_bytes2)

                # wrong password should fail
                priv3, pub_bytes3 = cu.generate_or_load_keys(name, "wrong_password")
                self.assertIsNone(priv3)
                self.assertIsNone(pub_bytes3)

            finally:
                os.chdir(old_cwd)

if __name__ == "__main__":
    unittest.main()
