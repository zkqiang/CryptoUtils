# -*- coding: utf-8 -*-

import base64

from Crypto.Cipher import AES


class AESCrypto(object):

    def __init__(self, key: str, mode: str, no_padding: bool):
        self.key = key[:16].encode()
        self.mode = getattr(AES, 'MODE_' + mode.upper())
        self.no_padding = no_padding

    def encrypt(self, plain_text: str, iv: str = None) -> str:
        """
        加密
        :param plain_text: 明文
        :param iv: 向量值，只在模式为 `MODE_CBC`, `MODE_CFB`,
            `MODE_OFB`, `MODE_OPENPGP` 需要指定
        :return: 密文
        """
        iv = iv if iv is None else iv.encode()
        crypto = AES.new(self.key, self.mode, iv=iv)
        cipher_bytes = crypto.encrypt(
            self._pad(plain_text).encode())
        cipher_text = base64.b64encode(cipher_bytes)
        return cipher_text.decode()

    def decrypt(self, cipher_text: str, iv: str = None) -> str:
        """
        解密
        :param cipher_text: 密文
        :param iv: 同 encrypt
        :return: 明文
        """
        cipher_bytes = base64.b64decode(cipher_text)
        iv = iv if iv is None else iv.encode()
        crypto = AES.new(self.key, self.mode, iv=iv)
        plain_text = crypto.decrypt(cipher_bytes).decode()
        return self._unpad(plain_text)

    def _pad(self, text: str) -> str:
        """
        填充
        NoPadding 填充是区块不足倍数时补零字节码
        PKCS5Padding 填充是区块不足倍数时补缺少位数的字节码
        :param text: str
        :return: str
        """
        size = AES.block_size
        pad_size = size - len(text) % size
        if self.no_padding:
            return text + pad_size * '\0'
        return text + pad_size * chr(pad_size)

    def _unpad(self, text: str) -> str:
        """
        去除填充
        NoPadding 填充是去除末尾的零字节码
        PKCS5Padding 填充是根据最后一位的字节码去除对应的位数
        :param text: str
        :return: str
        """
        if self.no_padding:
            return text.rstrip('\0')
        return text[:-ord(text[-1])]
