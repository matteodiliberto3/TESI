import os
import sys
import json
import pickle
import argparse
import secrets
import shutil
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional
from http.server import BaseHTTPRequestHandler

import numpy as np
from fastapi import FastAPI, HTTPException, Body, Header
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from feature_store.store import FeatureStore
from pipeline.crypto_signer import ModelConsumerVerifier, SecurityError
from pipeline.train import load_model_safetensors

class FraudInferenceService:
    """
    Production inference service fetching features and evaluating transactions.
    Acts as an unprivileged consumer: possesses and uses ONLY the public key for verification.
    """
    def __init__(
        self,
        mode: str = "signed_pickle",
        model_path: Optional[Path] = None,
        sig_path: Optional[Path] = None,
        public_key_path: Optional[Path] = None,
        private_key_path: Optional[Path] = None
    ):
        self.mode = mode
        self.fs = FeatureStore()
        pub_key = public_key_path or config.PUBLIC_KEY_FILE
        priv_key = private_key_path or config.PRIVATE_KEY_FILE
        self.verifier = ModelConsumerVerifier(pub_key)
        self.model = None
        self.verification_passed = False
        self.signature_verified = False
        self.format_safe = False
        self.model_path = model_path
        self.load_error = None

        # Verify that private key is NOT accessible (Least Privilege / PoLP check)
        try:
            self.private_key_isolated = not priv_key.exists()
        except (PermissionError, OSError):
            self.private_key_isolated = True

        self._load_model(mode, model_path, sig_path)

    def _load_model(self, mode: str, model_path: Optional[Path], sig_path: Optional[Path]):
        # Normalize insecure_pickle alias to vulnerable_pickle
        if mode in ("insecure_pickle", "vulnerable_pickle"):
            mode = "vulnerable_pickle"

        self.mode = mode
        self.load_error = None
        self.signature_verified = False
        self.format_safe = False
        try:
            if mode == "vulnerable_pickle":
                path = model_path or config.CLEAN_MODEL_PICKLE
                self.model_path = path
                with open(path, "rb") as f:
                    self.model = pickle.load(f)
                self.verification_passed = False
                self.signature_verified = False
                self.format_safe = False

            elif mode == "signed_pickle":
                path = model_path or config.CLEAN_MODEL_PICKLE
                sig = sig_path or config.SIGNATURE_FILE
                self.model_path = path
                # In-memory atomic deserialization: physically eliminates TOCTOU window
                self.model = self.verifier.load_verified_pickle(path, sig)
                self.verification_passed = True
                self.signature_verified = True
                self.format_safe = False

            elif mode == "mlflow_statsmodels":
                path = model_path or (config.ARTIFACTS_DIR / "mlflow_clean_model")
                self.model_path = path

                # Defense-in-Depth Sandbox Preparation:
                # Copy model files to a private temporary directory, rejecting external symlinks,
                # perform cryptographic manifest & signature verification in the sandbox, then load.
                sandbox_dir = tempfile.mkdtemp(prefix="mlflow_gate_secure_")
                try:
                    sandbox_path = Path(sandbox_dir)
                    if path.is_dir():
                        dest_model_dir = sandbox_path / "model"

                        def check_symlinks(src, names):
                            ignored = []
                            for name in names:
                                item = Path(src) / name
                                if item.is_symlink():
                                    target = item.resolve()
                                    if not target.is_relative_to(path.resolve()):
                                        raise SecurityError(f"Symlink {item.name} escapes model directory -> {target}")
                            return ignored

                        shutil.copytree(path, dest_model_dir, ignore=check_symlinks)
                    else:
                        dest_model_dir = sandbox_path
                        shutil.copy2(path, sandbox_path / path.name)

                    # Full package authentication via Cryptographic Package Manifest is MANDATORY
                    # Protected mode mlflow_statsmodels strictly forbids single-file fallback signatures or unsigned packages
                    manifest_file = dest_model_dir / "mlflow_manifest.json"
                    manifest_sig = dest_model_dir / "mlflow_manifest.json.sig"

                    if not manifest_file.exists() or not manifest_sig.exists():
                        raise SecurityError(
                            f"[Gate Alert] Cryptographic manifest ({manifest_file.name}) or signature ({manifest_sig.name}) missing "
                            f"in MLflow package at {path}. Single-file fallback signatures (e.g. model.statsmodels.sig) and "
                            f"unsigned packages are strictly disallowed under protected MLflow security policy."
                        )

                    pkg_res = self.verifier.verify_mlflow_package(dest_model_dir)
                    if not pkg_res.is_valid:
                        raise SecurityError(
                            f"[Gate Alert] MLflow package manifest verification failed: "
                            f"{pkg_res.status} - {pkg_res.detail}"
                        )

                    self.verification_passed = True
                    self.signature_verified = True

                    import mlflow.statsmodels
                    self.model = mlflow.statsmodels.load_model(str(dest_model_dir))
                    self.format_safe = False
                finally:
                    shutil.rmtree(sandbox_dir, ignore_errors=True)

            elif mode == "safetensors":
                path = model_path or config.SECURE_MODEL_SAFETENSORS
                self.model_path = path
                self.model = load_model_safetensors(path)
                self.verification_passed = True
                self.signature_verified = False
                self.format_safe = True

            else:
                raise ValueError(f"Unsupported inference mode: {mode}")
        except Exception as e:
            self.model = None
            self.verification_passed = False
            self.signature_verified = False
            self.format_safe = False
            self.load_error = str(e)
            raise e

    def predict_features(self, feature_dict: Dict[str, float]) -> Dict[str, Any]:
        if self.model is None:
            raise RuntimeError("Model is not loaded or initialization failed")
            
        # Support Statsmodels results (e.g. LogitResults with variable params dimension)
        if hasattr(self.model, "params"):
            num_params = len(self.model.params)
            if num_params == 3:
                # const + 2 features (amount, transaction_hour)
                vec = np.array([[1.0, float(feature_dict.get("amount", 0.0)), float(feature_dict.get("transaction_hour", 12.0))]])
            elif num_params == 7:
                # const + 6 features
                vec = np.array([[
                    1.0,
                    float(feature_dict.get("amount", 0.0)),
                    float(feature_dict.get("transaction_hour", 12.0)),
                    float(feature_dict.get("distance_from_home", 5.0)),
                    float(feature_dict.get("velocity_last_24h", 1)),
                    float(feature_dict.get("foreign_transaction", 0)),
                    float(feature_dict.get("high_risk_merchant", 0))
                ]])
            else:
                vec = np.ones((1, num_params))
                feature_vals = [
                    float(feature_dict.get("amount", 0.0)),
                    float(feature_dict.get("transaction_hour", 12.0)),
                    float(feature_dict.get("distance_from_home", 5.0)),
                    float(feature_dict.get("velocity_last_24h", 1)),
                    float(feature_dict.get("foreign_transaction", 0)),
                    float(feature_dict.get("high_risk_merchant", 0))
                ]
                for idx, val in enumerate(feature_vals[:num_params - 1]):
                    vec[0, idx + 1] = val
            raw_prob = float(self.model.predict(vec)[0])
            pred = int(raw_prob >= 0.5)
            prob = raw_prob
        else:
            vector = np.array([[
                feature_dict.get("amount", 0.0),
                feature_dict.get("transaction_hour", 12.0),
                feature_dict.get("distance_from_home", 5.0),
                feature_dict.get("velocity_last_24h", 1),
                feature_dict.get("foreign_transaction", 0),
                feature_dict.get("high_risk_merchant", 0)
            ]])
            pred = int(self.model.predict(vector)[0])
            prob = float(self.model.predict_proba(vector)[0, 1]) if hasattr(self.model, "predict_proba") else float(pred)

        return {
            "is_fraud": pred,
            "fraud_probability": round(prob, 4),
            "features_used": feature_dict
        }

    def predict_for_user(self, entity_user_id: str) -> Dict[str, Any]:
        features = self.fs.get_online_features(entity_user_id)
        if features is None:
            return {"error": f"User {entity_user_id} not found in Online Feature Store"}
        res = self.predict_features(features)
        res["entity_user_id"] = entity_user_id
        return res

# Global service instance
service: Optional[FraudInferenceService] = None

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    global service
    mode = os.getenv("INFERENCE_MODE", "signed_pickle")
    try:
        service = FraudInferenceService(mode=mode)
    except Exception as e:
        print(f"[Consumer Startup Warning] Initial model load failed: {e}")
    yield

app = FastAPI(
    title="MLOps Insecure Deserialization Consumer",
    description="Unprivileged FastAPI Inference Worker demonstrating supply chain security controls",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    global service
    if service and service.model is not None:
        return {
            "status": "HEALTHY",
            "mode": service.mode,
            "worker_pid": os.getpid(),
            "model_class": service.model.__class__.__name__,
            "signature_verified": getattr(service, "signature_verified", False),
            "format_safe": getattr(service, "format_safe", False),
            "public_key_present": service.verifier.public_key_path.exists(),
            "private_key_absent_from_consumer": service.private_key_isolated
        }
    return JSONResponse(
        status_code=503,
        content={
            "status": "UNHEALTHY",
            "worker_pid": os.getpid(),
            "mode": service.mode if service else "uninitialized",
            "error": service.load_error if service else "Service not created"
        }
    )

@app.get("/info")
def info():
    global service
    return {
        "worker_pid": os.getpid(),
        "role": "CONSUMER",
        "mode": service.mode if service else None,
        "model_loaded": service.model is not None if service else False,
        "model_path": str(service.model_path) if service and service.model_path else None,
        "verification_passed": service.verification_passed if service else False,
        "signature_verified": getattr(service, "signature_verified", False) if service else False,
        "format_safe": getattr(service, "format_safe", False) if service else False,
        "private_key_isolated": service.private_key_isolated if service else True,
        "security_policy": "Least Privilege (cap_drop: ALL, read-only artifacts)"
    }

@app.post("/predict")
def predict(payload: Dict[str, Any] = Body(...)):
    global service
    if not service or service.model is None:
        raise HTTPException(
            status_code=503,
            detail=f"Model unavailable. Last error: {service.load_error if service else 'Service uninitialized'}"
        )
    try:
        if "entity_user_id" in payload:
            return service.predict_for_user(payload["entity_user_id"])
        return service.predict_features(payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/reload")
def reload_model(
    payload: Optional[Dict[str, Any]] = Body(None),
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Administrative Endpoint for Hot-Reloading Model Artifacts.

    Contract:
      - Authentication: Requires valid secret token matching environment MLOPS_ADMIN_TOKEN via:
          * Header 'Authorization: Bearer <TOKEN>' OR
          * Header 'X-Admin-Token: <TOKEN>'
          * Fails with HTTP 503 if server secret is unconfigured.
          * Fails with HTTP 401 if token is absent, empty, or mismatched (timing-safe check).
      - Request Body (JSON):
          * 'mode' OR 'model_format' (string, required): One of:
              - 'signed_pickle' (verified RSA-PSS single pickle)
              - 'safetensors' (safe declarative tensor format)
              - 'mlflow_statsmodels' (full package manifest verified MLflow directory)
              - 'vulnerable_pickle' (deliberately unverified pickle; alias 'insecure_pickle')
          * Conflicting 'mode' and 'model_format' parameters are rejected with HTTP 400.
          * 'insecure_pickle' is strictly normalized to 'vulnerable_pickle' prior to policy enforcement.
          * 'model_path' (string, optional): Filesystem path within 'artifacts/' directory.
          * 'sig_path' (string, optional): Cryptographic signature path within 'artifacts/'.
      - Security & Isolation:
          * Strict path confinement: Paths outside artifacts/ rejected with HTTP 403.
          * Insecure pickle reload disallowed by default unless ALLOW_INSECURE_RELOAD='true' (HTTP 403).
          * Atomic Candidate Loading: Verifies and instantiates model before state transition.
            On verification or load failure, previous active model remains intact and HTTP 400/403 is returned.
    """
    global service
    p = None
    s = None
    allowed_dir = config.ARTIFACTS_DIR.resolve()

    # Extract token from X-Admin-Token or Authorization header
    token = x_admin_token
    if not token and authorization:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
        elif len(parts) == 1:
            token = parts[0]

    # Authentication Enforcement: Require non-empty administrative token from external secret
    admin_token = os.getenv("MLOPS_ADMIN_TOKEN")
    if not admin_token or not admin_token.strip():
        raise HTTPException(
            status_code=503,
            detail="Administrative reload disabled: MLOPS_ADMIN_TOKEN secret is not configured in environment"
        )
    if not token or not secrets.compare_digest(admin_token.strip(), token.strip()):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Valid authentication token required for model reload"
        )

    # Safe parsing of payload dictionary
    req = payload or {}
    raw_mode = req.get("mode")
    raw_fmt = req.get("model_format")

    if not raw_mode and not raw_fmt:
        raise HTTPException(
            status_code=400,
            detail="Bad Request: Missing required 'mode' or 'model_format' in reload body"
        )

    def normalize_mode_val(val: Optional[Any]) -> Optional[str]:
        if val is None:
            return None
        v = str(val).strip().lower()
        if v in ("insecure_pickle", "vulnerable_pickle"):
            return "vulnerable_pickle"
        return v

    norm_mode = normalize_mode_val(raw_mode)
    norm_fmt = normalize_mode_val(raw_fmt)

    # Reject conflicting parameters if both are provided
    if norm_mode is not None and norm_fmt is not None and norm_mode != norm_fmt:
        raise HTTPException(
            status_code=400,
            detail=f"Conflicting parameters: 'mode' ('{raw_mode}') and 'model_format' ('{raw_fmt}') specify different modes"
        )

    mode = norm_mode if norm_mode is not None else norm_fmt
    assert mode is not None

    model_path = req.get("model_path")
    sig_path = req.get("sig_path")

    # Policy Enforcement: Fail-closed by default for unverified pickle reload
    if mode == "vulnerable_pickle" and os.getenv("ALLOW_INSECURE_RELOAD", "false").lower() != "true":
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Unchecked pickle deserialization is disallowed by MLOps security policy"
        )

    if model_path:
        p = Path(model_path).resolve()
        if not p.is_relative_to(allowed_dir):
            raise HTTPException(status_code=403, detail="Access denied: model_path outside allowed artifacts directory")

    if sig_path:
        s = Path(sig_path).resolve()
        if not s.is_relative_to(allowed_dir):
            raise HTTPException(status_code=403, detail="Access denied: sig_path outside allowed artifacts directory")

    # Atomic reload: verify and load into a temporary candidate first.
    # If loading or cryptographic verification fails, the existing service remains intact (no corrupted state).
    try:
        candidate = FraudInferenceService(mode=mode, model_path=p, sig_path=s)
        if candidate.model is None or candidate.load_error:
            raise SecurityError(candidate.load_error or "Candidate model verification or load failed")

        service = candidate
        return {
            "status": "SUCCESS",
            "mode": mode,
            "worker_pid": os.getpid(),
            "model_class": service.model.__class__.__name__,
            "verification_passed": service.verification_passed,
            "signature_verified": getattr(service, "signature_verified", False),
            "format_safe": getattr(service, "format_safe", False)
        }
    except Exception as e:
        status_code = 403 if isinstance(e, (SecurityError, PermissionError)) else 400
        raise HTTPException(
            status_code=status_code,
            detail={
                "status": "REJECTED",
                "mode": mode,
                "worker_pid": os.getpid(),
                "error": str(e),
                "verification_passed": False,
                "signature_verified": False,
                "format_safe": False
            }
        )

@app.get("/audit-log")
def read_audit_log():
    audit_file = config.REPORTS_DIR / "deserialization_audit_proof.log"
    if not audit_file.exists():
        return {"exists": False, "trace": None}
    try:
        content = audit_file.read_text(encoding="utf-8")
        return {"exists": True, "trace": content.strip()}
    except Exception as e:
        return {"exists": True, "error": str(e)}

class InferenceHTTPHandler(BaseHTTPRequestHandler):
    """Legacy HTTP handler provided for backward compatibility with isolated test harnesses."""
    service: Optional[FraudInferenceService] = None

    def _send_json(self, status_code: int, data: Dict[str, Any]):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ["/health", "/"]:
            if self.service and self.service.model is not None and (self.service.verification_passed or self.service.mode == "safetensors"):
                self._send_json(200, {
                    "status": "HEALTHY",
                    "mode": self.service.mode,
                    "model_class": self.service.model.__class__.__name__,
                    "signature_verified": getattr(self.service, "signature_verified", self.service.verification_passed),
                    "format_safe": getattr(self.service, "format_safe", self.service.mode == "safetensors"),
                    "public_key_present": self.service.verifier.public_key_path.exists(),
                    "private_key_absent_from_consumer": self.service.private_key_isolated
                })
            else:
                self._send_json(503, {
                    "status": "UNHEALTHY",
                    "error": "Model not loaded or signature verification failed"
                })
        else:
            self._send_json(404, {"error": "Endpoint not found"})

    def do_POST(self):
        if self.path == "/predict":
            if not self.service or self.service.model is None:
                self._send_json(503, {"error": "Model service unavailable"})
                return
            try:
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len)
                payload = json.loads(body.decode("utf-8")) if body else {}

                if "entity_user_id" in payload:
                    res = self.service.predict_for_user(payload["entity_user_id"])
                else:
                    res = self.service.predict_features(payload)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": f"Invalid payload: {str(e)}"})
        else:
            self._send_json(404, {"error": "Endpoint not found"})

    def log_message(self, format, *args):
        sys.stderr.write(f"[Legacy HTTP Consumer] {self.address_string()} - {format % args}\n")

def start_inference_server(
    host: str = "127.0.0.1",
    port: int = 8000,
    mode: str = "signed_pickle"
):
    os.environ["INFERENCE_MODE"] = mode
    print("=" * 70)
    print("      MLOps Unprivileged FastAPI Inference Consumer Service")
    print(f"      Mode: {mode} | Address: http://{host}:{port} | PID: {os.getpid()}")
    print("=" * 70)
    uvicorn.run(app, host=host, port=port, log_level="info")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unprivileged FastAPI MLOps Inference Service")
    parser.add_argument("--mode", default=os.getenv("INFERENCE_MODE", "signed_pickle"), choices=["signed_pickle", "safetensors", "vulnerable_pickle", "mlflow_statsmodels"])
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    parser.add_argument("--host", default=os.getenv("HOST", "127.0.0.1"))
    parser.add_argument("--test-only", action="store_true", help="Execute verification check and exit")
    args = parser.parse_args()

    if args.test_only:
        svc = FraudInferenceService(mode=args.mode)
        print(f"[Inference Check] Service initialized (Mode: {args.mode}). Verified: {svc.verification_passed}")
    else:
        start_inference_server(host=args.host, port=args.port, mode=args.mode)
