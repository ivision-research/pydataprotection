"""
Decrypt data protected with ASP.NET Core DataProtection.Protect.

Example usage:

    dp = DataProtection("Bitwarden")

    # Option 1
    dp.import_key("/home/user/.aspnet/DataProtection-Keys/key-00000000-0000-0000-0000-000000000000.xml")
    # Option 2
    dp.set_key(
        key,  # bytes
        "AES_256_CBC",
        "HMACSHA256",
        key_id="00000000-0000-0000-0000-000000000000",
    )

    print(dp.unprotect(protected_data, "DatabaseFieldProtection"))
"""

import base64
import hmac
from struct import pack
from uuid import UUID

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, CounterLocation, Mode


class DataProtection(object):
    key = None

    def __init__(self, name):
        self.name = name

    def unprotect(self, protected, purpose):
        assert self.key
        assert protected[:4] == b"\x09\xf0\xc9\xf0"
        protected_key_id = UUID(bytes_le=protected[4:20])
        assert protected_key_id.int == self.key_id.int
        key_modifier = protected[20:36]
        iv = protected[36:52]
        ctxt = protected[52:-32]
        assert len(ctxt) % 16 == 0
        hmac_digest = protected[-32:]

        kdf = KBKDFHMAC(
            algorithm=hashes.SHA512(),
            mode=Mode.CounterMode,
            length=self.enc_keysize + self.hmac_size,
            rlen=4,
            llen=4,
            location=CounterLocation.BeforeFixed,
            label=self.aad(
                [
                    self.name,
                    purpose,
                ]
            ),
            context=self.context_header + key_modifier,
            fixed=None,
        ).derive(self.key)
        k_e = kdf[: self.enc_keysize]
        k_h = kdf[self.enc_keysize :]

        if hmac.new(k_h, iv + ctxt, self.hmac_string).digest() != hmac_digest:
            raise ValueError("Failed to verify HMAC")
        cipher = Cipher(algorithms.AES(k_e), modes.CBC(iv)).decryptor()
        data = cipher.update(ctxt) + cipher.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(data) + unpadder.finalize()

    def import_key(self, path):
        import xml.etree.ElementTree as ET

        tree = ET.parse(path)
        self.set_key(
            base64.b64decode(tree.find("./descriptor/descriptor/masterKey/value").text),
            tree.find("./descriptor/descriptor/encryption").attrib["algorithm"],
            tree.find("./descriptor/descriptor/validation").attrib["algorithm"],
            tree.getroot().attrib["id"],
        )

    def set_key(self, key: bytes, enc_algo, hmac_algo, key_id):
        self.key = key
        self.enc_algo = enc_algo
        self.hmac_algo = hmac_algo
        self.key_id = UUID(key_id)

        if self.enc_algo.startswith("AES_256"):
            self.enc_keysize = 32
        elif self.enc_algo.startswith("AES_192"):
            self.enc_keysize = 24
        elif self.enc_algo.startswith("AES_128"):
            self.enc_keysize = 16
        if self.enc_algo.startswith("AES"):
            self.enc_blocksize = 16
        if self.hmac_algo == "HMACSHA256":
            self.hmac_size = 32
        elif self.hmac_algo == "HMACSHA512":
            self.hmac_size = 64

        # TODO error checking

    @property
    def context_header(self):
        context_header = b"\x00\x00"
        context_header += pack(">I", self.enc_keysize)  # key length
        context_header += pack(">I", self.enc_blocksize)  # block size
        context_header += pack(">I", self.hmac_size)  # hmac key size
        context_header += pack(">I", self.hmac_size)  # hmac digest size

        kdf = KBKDFHMAC(
            algorithm=hashes.SHA512(),
            mode=Mode.CounterMode,
            length=self.enc_keysize + self.hmac_size,
            rlen=4,
            llen=4,
            location=CounterLocation.BeforeFixed,
            label=b"",
            context=b"",
            fixed=None,
        ).derive(b"")
        k_e = kdf[: self.enc_keysize]
        k_h = kdf[self.enc_keysize :]

        enc = Cipher(algorithms.AES(k_e), modes.CBC(16 * b"\x00")).encryptor()
        padder = padding.PKCS7(128).padder()
        context_header += enc.update(padder.finalize()) + enc.finalize()

        context_header += hmac.new(k_h, b"", self.hmac_string).digest()

        return context_header

    def aad(self, purposes):
        res = b"\x09\xf0\xc9\xf0" + self.key_id.bytes_le + pack(">I", len(purposes))
        for purpose in purposes:
            res += pack(">B", len(purpose)) + purpose.encode("utf8")
        return res

    @property
    def hmac_string(self):
        return self.hmac_algo[4:].lower()

__all__ = ["DataProtection"]
