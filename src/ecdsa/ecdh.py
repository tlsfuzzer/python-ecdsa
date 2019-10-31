"""
Class for performing Elliptic-curve Diffie-Hellman (ECDH) operations.
"""

from .util import number_to_string
from .ellipticcurve import INFINITY
from .keys import SigningKey, VerifyingKey


__all__ = ["ECDH", "NoKeyError", "InvalidPublicKeyCurveError",
           "InvalidSharedSecretError"]


class NoKeyError(AssertionError):
    """ECDH. Key not found but needed for operation."""

    pass


class InvalidPublicKeyCurveError(AssertionError):
    """ECDH. Raised in case not equal curves in public key and private key."""

    pass


class InvalidSharedSecretError(AssertionError):
    """ECDH. Raised in case the shared secret we obtained is an INFINITY."""

    pass


class ECDH(object):
    """
    Elliptic-curve Diffie-Hellman (ECDH). A key agreement protocol.
    Allows two parties, each having an elliptic-curve public-private key 
    pair, to establish a shared secret over an insecure channel
    """""

    def __init__(self):
        self.privateKey = None
        self.publicKey = None
        pass

    def _get_shared_secret(self, remote_public_key):
        if self.privateKey is None:
            raise NoKeyError("Private key needs to be set to create shared secret")
        if self.publicKey is None:
            raise NoKeyError("Public key needs to be set to create shared secret")

        if self.privateKey.curve != remote_public_key.curve:
            raise InvalidPublicKeyCurveError(
                "Curves for public key and private key is not equal.")

        # shared secret = PUBKEYtheirs * PRIVATEKEYours
        result = remote_public_key.pubkey.point * self.privateKey.privkey.secret_multiplier
        if result == INFINITY:
            raise InvalidSharedSecretError(
                "Invalid shared secret (INFINITY).")

        return result.x()

    def GeneratePrivateKey(self, kcurve):
        self.privateKey = SigningKey.generate(curve=kcurve)
        if not (self.publicKey is None) and \
                self.publicKey.curve != self.privateKey.curve:
            self.publicKey = None

    def LoadPrivateKeyFromStr(self, private_key, kcurve):
        self.privateKey = SigningKey.from_string(private_key, curve=kcurve)
        if not (self.publicKey is None) and \
                self.publicKey.curve != kcurve:
            self.publicKey = None

    def GetMyPublicKey(self):
        return self.privateKey.get_verifying_key()

    def LoadPublicKey(self, public_key):
        if self.privateKey is None:
            raise NoKeyError("Private key needs to be set to import public key")
        if self.privateKey.curve != public_key.curve:
            raise InvalidPublicKeyCurveError(
                "Curves for public key and private key is not equal.")
        self.publicKey = public_key

    def LoadPublicKeyFromStr(self, public_key_str):
        return self.LoadPublicKey(
            VerifyingKey.from_string(public_key_str, self.privateKey.curve))

    def GenerateSharedSecret(self):
        return number_to_string(
                    self._get_shared_secret(self.publicKey),
                    self.privateKey.curve.order)


