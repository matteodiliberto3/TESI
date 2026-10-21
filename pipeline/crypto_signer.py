import os
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import config

class ModelProducerSigner:
    """
    Authorized producer entity (e.g. secure CI/CD training runner).
    Possesses the private key and signs compiled ML model artifacts.
    Aligns with SLSA Level 3 and Cosign/Sigstore signing specification.
    """
    def __init__(
        self,
        private_key_path: Path = config.PRIVATE_KEY_FILE,
        public_key_path: Path = config.PUBLIC_KEY_FILE,
        auto_generate_dev_keys: bool = False
    ):
        self.private_key_path = Path(private_key_path)
        self.public_key_path = Path(public_key_path)
        if auto_generate_dev_keys:
            self._ensure_keys_exist()

    def _ensure_keys_exist(self):
        """Generates an RSA-2048 keypair if missing (Development / Local PoC only)."""
        if not self.private_key_path.exists() or not self.public_key_path.exists():
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            pem_private = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            self.private_key_path.parent.mkdir(parents=True, exist_ok=True)
            self.private_key_path.write_bytes(pem_private)

            pem_public = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.public_key_path.write_bytes(pem_public)

    def sign_artifact(self, artifact_path: Path, signature_output_path: Path) -> bytes:
        """Computes SHA-256 hash of artifact and signs it with the RSA private key."""
        artifact_path = Path(artifact_path)
        signature_output_path = Path(signature_output_path)

        if not artifact_path.exists():
            raise FileNotFoundError(f"Artifact {artifact_path} does not exist.")
        if not self.private_key_path.exists():
            raise PermissionError(f"Private key not accessible at {self.private_key_path}. Signing aborted.")

        data = artifact_path.read_bytes()
        private_key = serialization.load_pem_private_key(
            self.private_key_path.read_bytes(),
            password=None
        )
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        signature_output_path.parent.mkdir(parents=True, exist_ok=True)
        signature_output_path.write_bytes(signature)
        return signature

    sign = sign_artifact


class ModelConsumerVerifier:
    """
    Unprivileged consumer entity (e.g. staging gate or production inference worker).
    Strictly isolated: POSSESSES ONLY THE PUBLIC KEY.
    Cannot sign, cannot generate keys, operates in fail-closed mode.
    """
    def __init__(self, public_key_path: Path = config.PUBLIC_KEY_FILE):
        self.public_key_path = Path(public_key_path)

    def verify_artifact(self, artifact_path: Path, signature_path: Path) -> bool:
        """Verifies artifact bytes against cryptographic signature using public key only."""
        artifact_path = Path(artifact_path)
        signature_path = Path(signature_path)

        if not artifact_path.exists() or not signature_path.exists():
            return False
        if not self.public_key_path.exists():
            raise FileNotFoundError(f"Public key missing at {self.public_key_path}. Cannot verify artifact.")

        data = artifact_path.read_bytes()
        signature = signature_path.read_bytes()

        public_key = serialization.load_pem_public_key(
            self.public_key_path.read_bytes()
        )
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    verify = verify_artifact


class ArtifactSigner:
    """
    Unified interface maintaining backward compatibility with existing pipeline calls.
    Internally separates Producer (Signing) and Consumer (Verification) duties.
    """
    def __init__(
        self,
        private_key_path: Path = config.PRIVATE_KEY_FILE,
        public_key_path: Path = config.PUBLIC_KEY_FILE
    ):
        self.producer = ModelProducerSigner(private_key_path, public_key_path, auto_generate_dev_keys=True)
        self.consumer = ModelConsumerVerifier(public_key_path)

    def sign_artifact(self, artifact_path: Path, signature_output_path: Path) -> bytes:
        return self.producer.sign_artifact(artifact_path, signature_output_path)

    def verify_artifact(self, artifact_path: Path, signature_path: Path) -> bool:
        return self.consumer.verify_artifact(artifact_path, signature_path)

    sign = sign_artifact
    verify = verify_artifact
