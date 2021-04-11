"""
This is a straight forward implementation of RFC 5869

HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

http://tools.ietf.org/html/rfc5869

"""

import warnings

from Crypto.Hash import SHA512, HMAC


class HKDF:
    """
    HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869)

    usage:

    >> engine = HKDF(b"password", b"salt", digestmod=SHA256)
    >> key1 = engine.expand(b"info", length)

    This is equvalent to

    >> prk = HKDF.rfc_extract(b"password", b"salt", digest=SHA256)
    >> key1 = HKDF.rfc_expand(prk, b"info", lengta, digest=SHA256h)

    """
    @staticmethod
    def rfc_extract(key: bytes, salt: bytes=b"", digest=SHA512) -> bytes:
        """ The extract step from RFC 5869

            Coverts the key and the salt to a pseudorandom key using
            the given hash function.
        """
        if not salt:
            salt = b'\0' * digest.digest_size
        return HMAC.new(salt, key, digestmod=digest).digest()


    @staticmethod
    def rfc_expand(prk: bytes, info: bytes, length: int, digest=SHA512) -> bytes:
        """ The expand step from RFC 5896

            Take the result of rfc_extract (given as prk) and
            compute a key from this based on info and a requested length.

            digest must be the same as in the extract step.
        """
        if length < 0:
            raise ValueError("Parameter length must be greater or equal 0")
        if length > digest.digest_size * 255:
            raise ValueError(f"Parameter length must be less or equal {digest.digest_size * 255}")

        # generate key stream, stop when we have enought bytes

        keystream = []
        keystream_length = 0
        block_index = 0
        key_block = b""

        while keystream_length < length:
            block_index += 1
            data =  key_block + info + bytes([block_index % 256])
            key_block = HMAC.new(prk, data, digestmod=digest).digest()
            keystream.append(key_block)
            keystream_length += len(key_block)

        return b"".join(keystream)[:length]

    def __init__(self, key: bytes, salt: bytes=b"", digestmod=SHA512):
        self.__digest = digestmod
        self.__prk = self.rfc_extract(key, salt, digestmod)

    @property
    def digest_length(self):
        """ return the digest_length of the hash module """
        return self.__digest.digest_size

    @property
    def _prk(self):
        """ the pseudorandom key, computed from the input key and the salt
        """
        return self.__prk

    def expand(self, info: bytes, length: int) -> bytes:
        """ expand  a key for the given context (info)  in the given length
        """
        return self.rfc_expand(self.__prk, info, length, digest=self.__digest)

    def extract_key(self, info: bytes, length: int) -> bytes:
        """ Deprecated: use expand() instead """
        warnings.warn("deprecated, use expand() instead", DeprecationWarning)
        return self.expand(info, length)


