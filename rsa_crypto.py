# -*- coding: utf-8 -*-

import base64

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA


class RSACrypto(object):

    @staticmethod
    def encrypt(plain_text: str, public_key: str, block_size: int = 117) -> str:
        """
        加密
        :param plain_text: 明文
        :param public_key: 公钥
        :param block_size: 分段块的长度
        :return: 密文
        """
        plain_bytes = plain_text.encode()
        public_key = RSACrypto._format_public_key(public_key)
        key = RSA.import_key(public_key)
        crypto = PKCS1_v1_5.new(key)
        cipher_array = []
        # 分段加密
        for i in range(0, len(plain_bytes), block_size):
            cipher_array.append(crypto.encrypt(plain_bytes[i:i + block_size]))
        cipher_b64 = base64.b64encode(b''.join(cipher_array))
        return cipher_b64.decode()

    @staticmethod
    def decrypt(cipher_text: str, private_key: str, block_size: int = 128) -> str:
        """
        解密
        :param cipher_text: 密文
        :param private_key: 密钥
        :param block_size: 分段块的长度
        :return: 明文
        """
        private_key = RSACrypto._format_private_key(private_key)
        key = RSA.import_key(private_key)
        crypto = PKCS1_v1_5.new(key)
        cipher_bytes = base64.b64decode(cipher_text)
        plain_array = []
        # 分段解密
        for i in range(0, len(cipher_bytes), block_size):
            plain_array.append(crypto.decrypt(cipher_bytes[i:i + block_size]))
        plain_bytes = b''.join(plain_array)
        return plain_bytes.decode()

    @staticmethod
    def _format_public_key(public_key: str) -> str:
        """
        将公钥字符串处理成可识别的格式
        :param public_key: 公钥
        :return: str
        """

        start = '-----BEGIN PUBLIC KEY-----\n'
        end = '\n-----END PUBLIC KEY-----'
        if public_key.startswith(start):
            return start + public_key + end
        return public_key

    @staticmethod
    def _format_private_key(private_key: str) -> str:
        """
        将私钥字符串处理成可识别的格式
        :param private_key: 私钥
        :return: str
        """
        start = '-----BEGIN RSA PRIVATE KEY-----\n'
        end = '\n-----END RSA PRIVATE KEY-----'
        if private_key.startswith(start):
            return start + private_key + end
        return private_key
