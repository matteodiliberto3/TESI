import os
import sys
import argparse
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import config

def generate_keypair(
    private_key_path: Path = config.PRIVATE_KEY_FILE,
    public_key_path: Path = config.PUBLIC_KEY_FILE,
    key_size: int = 2048,
    overwrite: bool = False
) -> None:
    """
    Explicit provisioning of RSA keypair for PKI / SLSA Level 3 artifact signing.
    Strictly isolated from runtime workloads; must be invoked during infrastructure
    provisioning or CI/CD secret configuration.
    """
    priv_path = Path(private_key_path)
    pub_path = Path(public_key_path)

    if not overwrite and priv_path.exists() and pub_path.exists():
        return

    priv_path.parent.mkdir(parents=True, exist_ok=True)
    pub_path.parent.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    priv_path.write_bytes(pem_private)

    pem_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_path.write_bytes(pem_public)
    print(f"[PKI Setup] Successfully provisioned cryptographic keys ->\n  Private: {priv_path}\n  Public:  {pub_path}")

class ModelProducerSigner:
    """
    Authorized producer entity (e.g. secure CI/CD training runner).
    Possesses the private key and signs compiled ML model artifacts.
    Aligns with SLSA Level 3 and Cosign/Sigstore signing specification.
    Operates in fail-closed mode: does NOT auto-generate keys at runtime.
    """
    def __init__(
        self,
        private_key_path: Path = config.PRIVATE_KEY_FILE,
        public_key_path: Path = config.PUBLIC_KEY_FILE
    ):
        self.private_key_path = Path(private_key_path)
        self.public_key_path = Path(public_key_path)

        if not self.private_key_path.exists():
            raise FileNotFoundError(
                f"Private signing key missing at '{self.private_key_path}'. "
                "Signing requires authorized build/producer credentials. "
                "Keys must be provisioned via 'generate_keypair()' or the deployment pipeline."
            )

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
    Backward-compatible unified interface for integration tests.
    Delegates to ModelProducerSigner and ModelConsumerVerifier.
    Strictly respects fail-closed least-privilege principles.
    """
    def __init__(
        self,
        private_key_path: Path = config.PRIVATE_KEY_FILE,
        public_key_path: Path = config.PUBLIC_KEY_FILE
    ):
        self.producer = ModelProducerSigner(private_key_path, public_key_path)
        self.consumer = ModelConsumerVerifier(public_key_path)

    def sign_artifact(self, artifact_path: Path, signature_output_path: Path) -> bytes:
        return self.producer.sign_artifact(artifact_path, signature_output_path)

    def verify_artifact(self, artifact_path: Path, signature_path: Path) -> bool:
        return self.consumer.verify_artifact(artifact_path, signature_path)

    sign = sign_artifact
    verify = verify_artifact

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cryptographic PKI Utility for MLOps Artifact Signing")
    parser.add_argument("--generate-keys", action="store_true", help="Explicitly provision new RSA keypair")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing key files if present")
    args = parser.parse_args()

    if args.generate_keys:
        generate_keypair(overwrite=args.overwrite)
    else:
        parser.print_help()
