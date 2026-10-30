import os
import sys
import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Any, Dict, Set

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import config

class SecurityError(PermissionError):
    """Raised when cryptographic verification or privilege boundaries are violated."""
    pass

@dataclass
class PackageVerificationResult:
    is_valid: bool
    status: str
    detail: str
    manifest_data: Optional[Dict[str, Any]] = None

    def __bool__(self) -> bool:
        return self.is_valid

def generate_keypair(
    private_key_path: Path = config.PRIVATE_KEY_FILE,
    public_key_path: Path = config.PUBLIC_KEY_FILE,
    key_size: int = 2048,
    overwrite: bool = False
) -> None:
    """
    Explicit provisioning of RSA keypair for PKI artifact signing.
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
    try:
        os.chmod(priv_path, 0o600)  # STRICT: Read/Write ONLY by the owner (PoLP)
    except Exception:
        pass

    pem_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_path.write_bytes(pem_public)
    try:
        os.chmod(pub_path, 0o644)  # Public key readable by unprivileged consumers
    except Exception:
        pass
    print(f"[PKI Setup] Successfully provisioned cryptographic keys ->\n  Private: {priv_path}\n  Public:  {pub_path}")

class ModelProducerSigner:
    """
    Authorized producer entity (e.g. secure CI/CD training runner).
    Possesses the private key and signs compiled ML model artifacts and package manifests.
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
        try:
            os.chmod(signature_output_path, 0o644)
        except Exception:
            pass
        return signature

    def sign_mlflow_package(
        self,
        package_dir: Path,
        manifest_filename: str = "mlflow_manifest.json"
    ) -> Path:
        """
        Signs an entire MLflow model package directory using a canonical cryptographic manifest.
        Authenticates MLmodel configuration, model pickle bytes, and all supporting resources.
        Produces:
          - package_dir / manifest_filename (canonical JSON)
          - package_dir / (manifest_filename + '.sig') (RSA-PSS SHA-256 signature)
        """
        package_dir = Path(package_dir).resolve()
        if not package_dir.is_dir():
            raise NotADirectoryError(f"Target {package_dir} is not a directory.")

        manifest_path = package_dir / manifest_filename
        sig_path = package_dir / f"{manifest_filename}.sig"

        files_meta = {}
        for root, dirs, files in os.walk(package_dir):
            dirs.sort()
            for f in sorted(files):
                full_path = Path(root) / f
                if full_path.is_symlink():
                    target = full_path.resolve()
                    if not target.is_relative_to(package_dir):
                        raise SecurityError(f"Symlink {full_path} escapes package directory: {target}")

                rel_str = full_path.relative_to(package_dir).as_posix()
                if rel_str in (manifest_filename, f"{manifest_filename}.sig"):
                    continue

                content = full_path.read_bytes()
                h = hashlib.sha256(content).hexdigest()
                files_meta[rel_str] = {
                    "sha256": h,
                    "size_bytes": len(content)
                }

        manifest = {
            "manifest_schema_version": "1.0",
            "package_format": "mlflow_statsmodels",
            "files": files_meta
        }

        canonical_bytes = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')
        manifest_path.write_bytes(canonical_bytes)
        self.sign_artifact(manifest_path, sig_path)
        return sig_path

    sign = sign_artifact


class ModelConsumerVerifier:
    """
    Unprivileged consumer entity (e.g. staging gate or production inference worker).
    Strictly isolated: POSSESSES ONLY THE PUBLIC KEY.
    Cannot sign, cannot generate keys, operates in fail-closed mode.
    """
    def __init__(self, public_key_path: Path = config.PUBLIC_KEY_FILE):
        self.public_key_path = Path(public_key_path)

    def verify_bytes(self, data: bytes, signature_bytes: bytes) -> bool:
        """Verifies raw artifact bytes directly against RSA-PSS cryptographic signature."""
        if not self.public_key_path.exists():
            raise FileNotFoundError(f"Public key missing at {self.public_key_path}. Cannot verify artifact.")

        public_key = serialization.load_pem_public_key(
            self.public_key_path.read_bytes()
        )
        try:
            public_key.verify(
                signature_bytes,
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

    def verify_artifact(self, artifact_path: Path, signature_path: Path) -> bool:
        """Verifies artifact bytes against cryptographic signature using public key only."""
        artifact_path = Path(artifact_path)
        signature_path = Path(signature_path)

        if not artifact_path.exists() or not signature_path.exists():
            return False

        data = artifact_path.read_bytes()
        signature = signature_path.read_bytes()
        return self.verify_bytes(data, signature)

    def verify_mlflow_package(
        self,
        package_dir: Path,
        manifest_filename: str = "mlflow_manifest.json"
    ) -> PackageVerificationResult:
        """
        Verifies the cryptographic integrity of an entire MLflow package directory.
        Rejects:
          - Modified MLmodel configuration (preventing data/code redirection)
          - Tampered model binaries
          - Missing files
          - Unauthorized extra files injected into the package
          - Path traversal and external symlinks
        """
        package_dir = Path(package_dir).resolve()
        if not package_dir.is_dir():
            return PackageVerificationResult(
                is_valid=False,
                status="NOT_A_DIRECTORY",
                detail=f"Target {package_dir} is not a directory"
            )

        manifest_path = package_dir / manifest_filename
        sig_path = package_dir / f"{manifest_filename}.sig"

        if not manifest_path.exists() or not sig_path.exists():
            return PackageVerificationResult(
                is_valid=False,
                status="MISSING_SIGNATURE",
                detail=f"Manifest ({manifest_path.name}) or signature ({sig_path.name}) missing in package"
            )

        manifest_bytes = manifest_path.read_bytes()
        sig_bytes = sig_path.read_bytes()

        if not self.verify_bytes(manifest_bytes, sig_bytes):
            return PackageVerificationResult(
                is_valid=False,
                status="INVALID_SIGNATURE",
                detail="RSA-PSS cryptographic signature verification failed for package manifest"
            )

        try:
            manifest = json.loads(manifest_bytes.decode('utf-8'))
        except Exception as e:
            return PackageVerificationResult(
                is_valid=False,
                status="INVALID_MANIFEST",
                detail=f"Failed to parse manifest JSON: {e}"
            )

        if manifest.get("manifest_schema_version") != "1.0":
            return PackageVerificationResult(
                is_valid=False,
                status="INVALID_MANIFEST",
                detail=f"Unsupported manifest schema version: {manifest.get('manifest_schema_version')}"
            )

        manifest_files = manifest.get("files")
        if not isinstance(manifest_files, dict) or not manifest_files:
            return PackageVerificationResult(
                is_valid=False,
                status="INVALID_MANIFEST",
                detail="Manifest contains empty or invalid 'files' mapping"
            )

        # 1. Path traversal checks on manifest entries
        for rel_str in manifest_files:
            rel_path = Path(rel_str)
            if rel_path.is_absolute():
                return PackageVerificationResult(
                    is_valid=False,
                    status="PATH_TRAVERSAL_VIOLATION",
                    detail=f"Absolute path disallowed in manifest: {rel_str}"
                )
            if ".." in rel_path.parts:
                return PackageVerificationResult(
                    is_valid=False,
                    status="PATH_TRAVERSAL_VIOLATION",
                    detail=f"Parent traversal '..' disallowed in manifest: {rel_str}"
                )

        # 2. Inspect physical files on disk
        physical_files = set()
        for root, dirs, files in os.walk(package_dir):
            for f in files:
                full_path = Path(root) / f
                if full_path.is_symlink():
                    target = full_path.resolve()
                    if not target.is_relative_to(package_dir):
                        return PackageVerificationResult(
                            is_valid=False,
                            status="SYMLINK_VIOLATION",
                            detail=f"Symlink {full_path.name} escapes package directory -> {target}"
                        )
                rel_str = full_path.relative_to(package_dir).as_posix()
                if rel_str in (manifest_filename, f"{manifest_filename}.sig"):
                    continue
                physical_files.add(rel_str)

        # Check for unauthorized extra files
        manifest_file_set = set(manifest_files.keys())
        unauthorized = physical_files - manifest_file_set
        if unauthorized:
            return PackageVerificationResult(
                is_valid=False,
                status="UNAUTHORIZED_FILE",
                detail=f"Unauthorized file(s) present in package: {sorted(list(unauthorized))}"
            )

        # Check for missing files
        missing = manifest_file_set - physical_files
        if missing:
            return PackageVerificationResult(
                is_valid=False,
                status="MISSING_FILE",
                detail=f"Required file(s) missing from package: {sorted(list(missing))}"
            )

        # 3. Verify digests and sizes for every file
        for rel_str, meta in manifest_files.items():
            full_path = package_dir / rel_str
            data = full_path.read_bytes()
            if len(data) != meta.get("size_bytes"):
                return PackageVerificationResult(
                    is_valid=False,
                    status="FILE_TAMPERED",
                    detail=f"Size mismatch for {rel_str}: expected {meta.get('size_bytes')}, got {len(data)}"
                )
            actual_hash = hashlib.sha256(data).hexdigest()
            if actual_hash != meta.get("sha256"):
                return PackageVerificationResult(
                    is_valid=False,
                    status="FILE_TAMPERED",
                    detail=f"Cryptographic SHA-256 digest mismatch for {rel_str}"
                )

        # 4. Semantic MLmodel integrity validation
        if "MLmodel" not in manifest_files:
            return PackageVerificationResult(
                is_valid=False,
                status="MISSING_MLMODEL",
                detail="Package manifest does not declare mandatory descriptor 'MLmodel'"
            )

        mlmodel_path = package_dir / "MLmodel"
        if not mlmodel_path.exists():
            return PackageVerificationResult(
                is_valid=False,
                status="MISSING_FILE",
                detail="Descriptor file 'MLmodel' does not exist in package directory"
            )

        try:
            import yaml
            mlmodel_raw = mlmodel_path.read_text(encoding="utf-8")
            mlmodel_content = yaml.safe_load(mlmodel_raw)
        except Exception as e:
            return PackageVerificationResult(
                is_valid=False,
                status="INVALID_YAML",
                detail=f"MLmodel descriptor failed YAML parsing: {e}"
            )

        if not isinstance(mlmodel_content, dict):
            return PackageVerificationResult(
                is_valid=False,
                status="INVALID_YAML",
                detail="MLmodel root element is not a YAML mapping dictionary"
            )

        flavors = mlmodel_content.get("flavors")
        if not isinstance(flavors, dict) or not flavors:
            return PackageVerificationResult(
                is_valid=False,
                status="INVALID_MLMODEL_FLAVORS",
                detail="MLmodel does not specify a valid 'flavors' dictionary"
            )

        if "statsmodels" not in flavors:
            return PackageVerificationResult(
                is_valid=False,
                status="INVALID_MLMODEL_FLAVORS",
                detail="MLmodel does not declare required 'statsmodels' flavor"
            )

        # Validate that all pointers in all flavors refer to files declared in the manifest and existing on disk
        for flavor_name, f_cfg in flavors.items():
            if not isinstance(f_cfg, dict):
                continue
            for ptr_key in ("data", "model_data", "code"):
                ptr_val = f_cfg.get(ptr_key)
                if ptr_val:
                    ptr_path = Path(ptr_val)
                    if ptr_path.is_absolute() or ".." in ptr_path.parts:
                        return PackageVerificationResult(
                            is_valid=False,
                            status="PATH_TRAVERSAL_VIOLATION",
                            detail=f"MLmodel flavor '{flavor_name}' pointer '{ptr_val}' attempts path traversal"
                        )
                    rel_ptr = ptr_path.as_posix()
                    if rel_ptr not in manifest_files:
                        return PackageVerificationResult(
                            is_valid=False,
                            status="UNAUTHORIZED_POINTER",
                            detail=f"MLmodel flavor '{flavor_name}' references file '{ptr_val}' not declared in signed manifest"
                        )
                    if not (package_dir / rel_ptr).exists():
                        return PackageVerificationResult(
                            is_valid=False,
                            status="MISSING_FILE",
                            detail=f"MLmodel flavor '{flavor_name}' references file '{ptr_val}' which is missing on disk"
                        )

        return PackageVerificationResult(
            is_valid=True,
            status="PACKAGE_AUTHORIZED",
            detail="Entire MLflow model package cryptographically verified via RSA-PSS manifest",
            manifest_data=manifest
        )

    def load_verified_pickle(self, artifact_path: Path, signature_path: Path) -> Any:
        """
        Atomically loads and deserializes a signed pickle model in-memory.
        Eliminates unprivileged filesystem race conditions between check and load:
        the exact byte buffer verified cryptographically against the signature is unpickled directly
        from memory via pickle.loads(), without reading the file from disk a second time.
        """
        import pickle
        artifact_path = Path(artifact_path)
        signature_path = Path(signature_path)

        if not artifact_path.exists():
            raise FileNotFoundError(f"Artifact {artifact_path} does not exist.")
        if not signature_path.exists():
            raise FileNotFoundError(f"Signature {signature_path} does not exist.")

        raw_bytes = artifact_path.read_bytes()
        sig_bytes = signature_path.read_bytes()

        if not self.verify_bytes(raw_bytes, sig_bytes):
            raise SecurityError(f"[CRITICAL SECURITY ALERT] Cryptographic verification failed for {artifact_path}!")

        return pickle.loads(raw_bytes)

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

    def sign_mlflow_package(self, package_dir: Path, manifest_filename: str = "mlflow_manifest.json") -> Path:
        return self.producer.sign_mlflow_package(package_dir, manifest_filename)

    def verify_artifact(self, artifact_path: Path, signature_path: Path) -> bool:
        return self.consumer.verify_artifact(artifact_path, signature_path)

    def verify_mlflow_package(self, package_dir: Path, manifest_filename: str = "mlflow_manifest.json") -> PackageVerificationResult:
        return self.consumer.verify_mlflow_package(package_dir, manifest_filename)

    def load_verified_pickle(self, artifact_path: Path, signature_path: Path) -> Any:
        return self.consumer.load_verified_pickle(artifact_path, signature_path)

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
