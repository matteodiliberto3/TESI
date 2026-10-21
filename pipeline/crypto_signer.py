import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import config

class ArtifactSigner:
    """
    Implements digital signature generation and verification for ML model artifacts.
    Aligns with Chapter 2.3 (SLSA/NIST) and Chapter 6.2 (Sigstore/Cosign principles).
    """
    def __init__(self, private_key_path: Path = config.PRIVATE_KEY_FILE, public_key_path: Path = config.PUBLIC_KEY_FILE):
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self._ensure_keys_exist()

    def _ensure_keys_exist(self):
        """Generates an RSA-2048 keypair if one does not already exist."""
        if not self.private_key_path.exists() or not self.public_key_path.exists():
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            # Serialize private key
            pem_private = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            self.private_key_path.parent.mkdir(parents=True, exist_ok=True)
            self.private_key_path.write_bytes(pem_private)

            # Serialize public key
            pem_public = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.public_key_path.write_bytes(pem_public)

    def sign_artifact(self, artifact_path: Path, signature_output_path: Path) -> bytes:
        """Computes SHA-256 hash of artifact and signs it with the private key."""
        if not artifact_path.exists():
            raise FileNotFoundError(f"Artifact {artifact_path} does not exist.")

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
        signature_output_path.write_bytes(signature)
        return signature

    def verify_artifact(self, artifact_path: Path, signature_path: Path) -> bool:
        """Verifies artifact bytes against the cryptographic signature using the public key."""
        if not artifact_path.exists() or not signature_path.exists():
            return False

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
