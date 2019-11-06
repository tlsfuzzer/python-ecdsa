"""
Class for performing Elliptic-curve Diffie-Hellman (ECDH) operations.
"""

from .util import number_to_string
from .ellipticcurve import INFINITY
from .keys import SigningKey, VerifyingKey


__all__ = ["ECDH", "NoKeyError", "InvalidCurveError",
           "InvalidSharedSecretError"]


class NoKeyError(AttributeError):
    """ECDH. Key not found but it is needed for operation."""

    pass


class NoCurveError(AttributeError):
    """ECDH. Curve not set but it is needed for operation."""

    pass


class InvalidCurveError(RuntimeError):
    """ECDH. Raised in case the public and private keys use different curves."""

    pass


class InvalidSharedSecretError(RuntimeError):
    """ECDH. Raised in case the shared secret we obtained is an INFINITY."""

    pass


class ECDH(object):
    """
    Elliptic-curve Diffie-Hellman (ECDH). A key agreement protocol.
    Allows two parties, each having an elliptic-curve public-private key 
    pair, to establish a shared secret over an insecure channel
    """""

    def __init__(self, curve=None, private_key=None, public_key=None):
        self.curve = curve
        self.private_key = None
        self.public_key = None
        if private_key:
            self.load_private_key(private_key)
        if public_key:
            self.load_received_public_key(public_key)

    def _get_shared_secret(self, remote_public_key):
        if self.private_key is None:
            raise NoKeyError(
                "Private key needs to be set to create shared secret")
        if self.public_key is None:
            raise NoKeyError(
                "Public key needs to be set to create shared secret")
        if not (self.private_key.curve == self.curve == remote_public_key.curve):
            raise InvalidCurveError(
                "Curves for public key and private key is not equal.")

        # shared secret = PUBKEYtheirs * PRIVATEKEYours
        result = remote_public_key.pubkey.point * self.private_key.privkey.secret_multiplier
        if result == INFINITY:
            raise InvalidSharedSecretError(
                "Invalid shared secret (INFINITY).")

        return result.x()

    def set_curve(self, key_curve):
        self.private_key = SigningKey.generate(curve=key_curve)

    def load_private_key(self, private_key):
        if self.curve is None:
            self.curve = private_key.curve
        if self.curve != private_key.curve:
            raise InvalidCurveError("Curve mismatch.")
        self.private_key = private_key
        return self.private_key.get_verifying_key()

    def generate_private_key(self):
        return self.load_private_key(SigningKey.generate(curve=self.curve))

    def load_private_key_bytes(self, private_key):
        return self.load_private_key(
            SigningKey.from_string(private_key, curve=self.curve))

    def load_private_key_der(self, private_key):
        return self.load_private_key(SigningKey.from_der(private_key))

    def load_private_key_pem(self, private_key):
        return self.load_private_key(SigningKey.from_pem(private_key))

    def get_public_key(self):
        return self.private_key.get_verifying_key()

    def load_received_public_key(self, public_key):
        if self.curve is None:
            self.curve = public_key.curve
        if self.curve != public_key.curve:
            raise InvalidCurveError("Curve mismatch.")
        self.public_key = public_key

    def load_received_public_key_bytes(self, public_key_str):
        return self.load_received_public_key(
            VerifyingKey.from_string(public_key_str, self.curve))

    def load_received_public_key_der(self, public_key_str):
        return self.load_received_public_key(VerifyingKey.from_der(public_key_str))

    def load_received_public_key_pem(self, public_key_str):
        return self.load_received_public_key(VerifyingKey.from_pem(public_key_str))

    def generate_sharedsecret_bytes(self):
        return number_to_string(
                    self.generate_sharedsecret(),
                    self.private_key.curve.order)

    def generate_sharedsecret(self):
        return self._get_shared_secret(self.public_key)
