# -*- coding: utf-8 -*-

import base64

from Crypto.Cipher import AES


class AESCrypto(object):

    def __init__(self, key: str, mode: str, no_padding: bool):
        self.key = key[:16].encode()
        self.mode = 'MODE_' + mode.upper()
        self._mode = getattr(AES, self.mode)
        self.no_padding = no_padding

    def encrypt(self, plain_text: str, iv: str = None) -> str:
        """
        加密
        :param plain_text: 明文
        :param iv: 向量值，只在模式为 `MODE_CBC`, `MODE_CFB`,
            `MODE_OFB`, `MODE_OPENPGP` 需要指定
        :return: 密文
        """
        cipher = self._new_cipher(iv)
        cipher_bytes = cipher.encrypt(
            self._pad(plain_text).encode())
        return base64.b64encode(cipher_bytes).decode()

    def decrypt(self, cipher_text: str, iv: str = None) -> str:
        """
        解密
        :param cipher_text: 密文
        :param iv: 同 encrypt
        :return: 明文
        """
        cipher_bytes = base64.b64decode(cipher_text)
        cipher = self._new_cipher(iv)
        plain_text = cipher.decrypt(cipher_bytes).decode()
        return self._unpad(plain_text)

    def _new_cipher(self, iv):
        if not iv:
            return AES.new(self.key, self._mode)
        assert self._mode in [
            AES.MODE_CBC,
            AES.MODE_CFB,
            AES.MODE_OFB,
            AES.MODE_OPENPGP
        ], 'iv is not applicable for %s mode' % self.mode
        return AES.new(self.key, self._mode, iv=iv.encode())

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
