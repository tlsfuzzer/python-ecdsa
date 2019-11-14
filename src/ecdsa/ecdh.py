"""
Class for performing Elliptic-curve Diffie-Hellman (ECDH) operations.
"""

from .util import number_to_string
from .ellipticcurve import INFINITY
from .keys import SigningKey, VerifyingKey


__all__ = ["ECDH", "NoKeyError", "NoCurveError", "InvalidCurveError",
           "InvalidSharedSecretError"]


class NoKeyError(Exception):
    """ECDH. Key not found but it is needed for operation."""

    pass


class NoCurveError(Exception):
    """ECDH. Curve not set but it is needed for operation."""

    pass


class InvalidCurveError(Exception):
    """ECDH. Raised in case the public and private keys use different curves."""

    pass


class InvalidSharedSecretError(Exception):
    """ECDH. Raised in case the shared secret we obtained is an INFINITY."""

    pass


class ECDH(object):
    """
    Elliptic-curve Diffie-Hellman (ECDH). A key agreement protocol.
    Allows two parties, each having an elliptic-curve public-private key 
    pair, to establish a shared secret over an insecure channel
    """""

    def __init__(self, curve=None, private_key=None, public_key=None):
        """
        ECDH init. Class can be init without parameters and then
        it will needs to set all of them for proper operation.
        :param curve: curve for operations
        :param private_key: `my` private key for ecdh
        :param public_key:  `their` public key for ecdh
        """
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
        """
        Set working curve for ecdh operation.
        :param key_curve: curve from `curves`
        :return: none
        """
        self.curve = key_curve

    def generate_private_key(self):
        """
        Generate local private key for ecdh operation with curve that was set.
        :return: public (verifying) key from this private key
        """
        return self.load_private_key(SigningKey.generate(curve=self.curve))

    def load_private_key(self, private_key):
        """
        Load private key from SigningKey (keys.py) class.
        Needs to have the same curve as was set with set_curve method.
        If curve is not set - it sets from this SigningKey
        :param private_key: Initialised SigningKey class
        :return: public (verifying) key from this private key
        """
        if self.curve is None:
            self.curve = private_key.curve
        if self.curve != private_key.curve:
            raise InvalidCurveError("Curve mismatch.")
        self.private_key = private_key
        return self.private_key.get_verifying_key()

    def load_private_key_bytes(self, private_key):
        """
        Load private key from plain bytes string.
        Uses current curve and checks if key length corresponds to
        the current curve.
        :param private_key: private key in bytes string format
        :return: public (verifying) key from this private key
        """
        return self.load_private_key(
            SigningKey.from_string(private_key, curve=self.curve))

    def load_private_key_der(self, private_key):
        """
        Load private key from DER string.
        Curve is get from DER and check if it the same as current curve

        Note, the only DER format supported is the RFC5915
        Look at keys.py:SigningKey.from_der()

        :param private_key: binary string with the DER encoding of private ECDSA key
        :return: public (verifying) key from this private key
        """
        return self.load_private_key(SigningKey.from_der(private_key))

    def load_private_key_pem(self, private_key):
        """
        Load private key from PEM string.
        Curve is get from PEM and check if it the same as current curve

        Note, the only PEM format supported is the RFC5915
        Look at keys.py:SigningKey.from_pem()
        it needs to have `EC PRIVATE KEY` section

        :param private_key: text with PEM-encoded private ECDSA key
        :return: public (verifying) key from this private key
        """
        return self.load_private_key(SigningKey.from_pem(private_key))

    def get_public_key(self):
        """
        Get public key from local private key.
        Usually needs to send it to remote party.
        :return: public (verifying) key from local private key
        """
        return self.private_key.get_verifying_key()

    def load_received_public_key(self, public_key):
        """
        Load public key from VerifyingKey (keys.py) class.
        Needs to have the same curve as set as current for ecdh operation.
        If curve is not set - it sets it from VerifyingKey
        :param public_key: Initialised VerifyingKey class
        :return:
        """
        if self.curve is None:
            self.curve = public_key.curve
        if self.curve != public_key.curve:
            raise InvalidCurveError("Curve mismatch.")
        self.public_key = public_key

    def load_received_public_key_bytes(self, public_key_str):
        """
        Load public key from bytes string.
        Uses current curve and checks if key length corresponds to
        the current curve.
        :param public_key_str: public key in bytes string format
        :return: none
        """
        return self.load_received_public_key(
            VerifyingKey.from_string(public_key_str, self.curve))

    def load_received_public_key_der(self, public_key_str):
        """
        Load public key from DER binary string.
        Curve is get from DER and check if it the same as current curve

        Note, the only DER format supported is the RFC5912
        Look at keys.py:VerifyingKey.from_der()

        :param public_key_str: binary string with the DER encoding of public ECDSA key
        :return: none
        """
        return self.load_received_public_key(VerifyingKey.from_der(public_key_str))

    def load_received_public_key_pem(self, public_key_str):
        """
        Load public key from PEM string.
        Curve is get from PEM and check if it the same as current curve

        Note, the only PEM format supported is the RFC5912
        Look at keys.py:VerifyingKey.from_pem()

        :param public_key_str: text with PEM-encoded public ECDSA key
        :return: none
        """
        return self.load_received_public_key(VerifyingKey.from_pem(public_key_str))

    def generate_sharedsecret_bytes(self):
        """
        Generate shared secret from local private key and remote public key.
        Needs to have initialized private key and received public key before
        generating.
        :return: shared secret in binary string format
        """
        return number_to_string(
                    self.generate_sharedsecret(),
                    self.private_key.curve.order)

    def generate_sharedsecret(self):
        """
        Generate shared secret from local private key and remote public key.
        Needs to have initialized private key and received public key before
        generating.

        It the same for local and remote parties.
        shared secret(local private key, remote public key ) ==
                shared secret (local public key, remote private key)

        :return: shared secret in int format
        """
        return self._get_shared_secret(self.public_key)
