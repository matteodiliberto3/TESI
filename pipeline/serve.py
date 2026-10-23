import os
import sys
import json
import pickle
import argparse
from pathlib import Path
from typing import Dict, Any, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
import numpy as np

import config
from feature_store.store import FeatureStore
from pipeline.crypto_signer import ModelConsumerVerifier
from pipeline.train import load_model_safetensors

class FraudInferenceService:
    """
    Simulates production inference service fetching features from online store and evaluating transactions.
    Strictly acts as an unprivileged consumer: possesses and uses ONLY the public key for verification.
    """
    def __init__(self, mode: str = "signed_pickle", model_path: Optional[Path] = None):
        self.mode = mode
        self.fs = FeatureStore()
        self.verifier = ModelConsumerVerifier(config.PUBLIC_KEY_FILE)
        self.model = None
        self.verification_passed = False

        # Verify that private key is NOT present in consumer environment (Least Privilege check)
        self.private_key_isolated = not config.PRIVATE_KEY_FILE.exists()

        if mode == "vulnerable_pickle":
            path = model_path or config.CLEAN_MODEL_PICKLE
            with open(path, "rb") as f:
                self.model = pickle.load(f)
            self.verification_passed = False

        elif mode == "signed_pickle":
            path = model_path or config.CLEAN_MODEL_PICKLE
            sig_path = config.SIGNATURE_FILE
            if not self.verifier.verify_artifact(path, sig_path):
                raise PermissionError(f"[CRITICAL SECURITY ALERT] Cryptographic verification failed for {path}!")
            with open(path, "rb") as f:
                self.model = pickle.load(f)
            self.verification_passed = True

        elif mode == "safetensors":
            path = model_path or config.SECURE_MODEL_SAFETENSORS
            self.model = load_model_safetensors(path)
            self.verification_passed = True

    def predict_features(self, feature_dict: Dict[str, float]) -> Dict[str, Any]:
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

class InferenceHTTPHandler(BaseHTTPRequestHandler):
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
            if self.service and self.service.model is not None:
                self._send_json(200, {
                    "status": "HEALTHY",
                    "mode": self.service.mode,
                    "model_class": self.service.model.__class__.__name__,
                    "signature_verified": self.service.verification_passed,
                    "public_key_present": config.PUBLIC_KEY_FILE.exists(),
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
        # Concise logging
        sys.stderr.write(f"[HTTP Consumer] {self.address_string()} - {format % args}\n")

def start_inference_server(
    host: str = "0.0.0.0",
    port: int = 8000,
    mode: str = "signed_pickle"
):
    print("=" * 70)
    print("      MLOps Unprivileged Inference Consumer Service")
    print(f"      Mode: {mode} | Address: http://{host}:{port}")
    print(f"      Security Boundary: Public Key Verified | Private Key Absent: {not config.PRIVATE_KEY_FILE.exists()}")
    print("=" * 70)

    service = FraudInferenceService(mode=mode)
    InferenceHTTPHandler.service = service
    server = HTTPServer((host, port), InferenceHTTPHandler)
    print(f"[Inference Consumer] Listening on http://{host}:{port} ...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Inference Consumer] Server shutting down cleanly.")
        server.server_close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unprivileged MLOps Inference Service")
    parser.add_argument("--mode", default=os.getenv("INFERENCE_MODE", "signed_pickle"), choices=["signed_pickle", "safetensors", "vulnerable_pickle"])
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--test-only", action="store_true", help="Execute verification check and exit")
    args = parser.parse_args()

    if args.test_only:
        svc = FraudInferenceService(mode=args.mode)
        print(f"[Inference Check] Service initialized successfully (Mode: {args.mode}). Signature verified: {svc.verification_passed}")
    else:
        start_inference_server(host=args.host, port=args.port, mode=args.mode)
