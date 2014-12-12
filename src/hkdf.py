"""
This is a straight forward implementation of RFC 5869

HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

http://tools.ietf.org/html/rfc5869

"""

from Crypto.Hash import SHA256, SHA512
from Crypto.Hash import HMAC


class HKDF(object):
    """
    Wrapper class for HKDF code
    """

    def __init__(self, key, salt="", digestmod=SHA512):
        self.__digest = digestmod
        self.__digest_len = self.__digest.digest_size

        if not salt:
            salt = '\0' * self.__digest_len

        self.__expanded_key = HMAC.new(salt,
                                       key,
                                       digestmod=self.__digest).digest()

    def extract_key(self, info, length):
        assert length <= self.__digest_len * 255

        # generate key stream, stop when we have enought bytes

        keystream = ""
        key_block = ""
        block_index = 1

        while len(keystream) < length:
            key_block = HMAC.new(self.__expanded_key,
                                 key_block + info + chr(block_index),
                                 digestmod=self.__digest).digest()
            block_index += 1
            keystream += key_block

        return keystream[:length]
