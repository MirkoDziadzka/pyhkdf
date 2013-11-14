"""
This is a straight forward implementation of RFC 5869

HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

http://tools.ietf.org/html/rfc5869

Test testcases are straight from the RFC
"""


import unittest

from Crypto.Hash import SHA256
from Crypto.Hash import SHA as SHA1

from hkdf import HKDF


class RFC5869Tests(unittest.TestCase):

    def test_rfc5869_Test_Case_1(self):
        digestmod = SHA256
        IKM = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".decode("hex")
        salt = "000102030405060708090a0b0c".decode("hex")
        info = "f0f1f2f3f4f5f6f7f8f9".decode("hex")

        OKM = HKDF(IKM, salt=salt, digestmod=digestmod).extract_key(info, 42)
        assert OKM == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865".decode("hex")

    def test_rfc5869_Test_Case_2(self):
        digestmod = SHA256
        IKM = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f".decode("hex")
        salt = "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf".decode("hex")
        info = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".decode("hex")

        OKM = HKDF(IKM, salt=salt, digestmod=digestmod).extract_key(info, 82)
        assert OKM == "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87".decode("hex")

    def test_rfc5869_Test_Case_3(self):
        digestmod = SHA256
        IKM = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".decode("hex")
        salt = "".decode("hex")
        info = "".decode("hex")

        OKM = HKDF(IKM, salt=salt, digestmod=digestmod).extract_key(info, 42)
        assert OKM == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8".decode("hex")

    def test_rfc5869_Test_Case_4(self):
        digestmod = SHA1
        IKM = "0b0b0b0b0b0b0b0b0b0b0b".decode("hex")
        salt = "000102030405060708090a0b0c".decode("hex")
        info = "f0f1f2f3f4f5f6f7f8f9".decode("hex")

        OKM = HKDF(IKM, salt=salt, digestmod=digestmod).extract_key(info, 42)
        assert OKM == "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896".decode("hex")

    def test_rfc5869_Test_Case_5(self):
        digestmod = SHA1
        IKM = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f".decode("hex")
        salt = "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf".decode("hex")
        info = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".decode("hex")

        OKM = HKDF(IKM, salt=salt, digestmod=digestmod).extract_key(info, 82)
        assert OKM == "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4".decode("hex")

    def test_rfc5869_Test_Case_6(self):
        digestmod = SHA1
        IKM = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".decode("hex")
        salt = "".decode("hex")
        info = "".decode("hex")

        OKM = HKDF(IKM, salt=salt, digestmod=digestmod).extract_key(info, 42)
        assert OKM == "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918".decode("hex")

    def test_rfc5869_Test_Case_7(self):
        digestmod = SHA1
        IKM = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c".decode("hex")
        # salt not provided
        info = "".decode("hex")

        OKM = HKDF(IKM, digestmod=digestmod).extract_key(info, 42)
        assert OKM == "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48".decode("hex")


if __name__ == '__main__':
    unittest.main()
