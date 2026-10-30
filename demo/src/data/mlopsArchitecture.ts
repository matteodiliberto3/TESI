import { MLOpsNode, ScenarioInfo } from '../types/mlops';

export const SCENARIOS: ScenarioInfo[] = [
  {
    id: 'baseline',
    name: 'Baseline Legittima'
  },
  {
    id: 'deserialization',
    name: 'Attacco Deserializzazione (MLflow CVE)'
  },
  {
    id: 'crypto-defense',
    name: 'Difesa Crittografica (Gate)'
  },
  {
    id: 'safe-format',
    name: 'Formato Sicuro (Safetensors)'
  }
];

export const MLOPS_NODES: MLOpsNode[] = [
  {
    id: 'producer',
    title: 'Training Producer',
    subtitle: 'CI/CD Build & Signing Pipeline',
    domain: 'Authorized CI/CD Signing Domain (PKI Authenticated)',
    defaultPosition: { x: 50, y: 130 },
    description: 'Ambiente di build containerizzato responsabile dell\'addestramento del modello e della generazione della firma crittografica RSA-PSS con chiave privata isolata.',
    pythonFile: 'pipeline/train.py & pipeline/crypto_signer.py',
    dockerSpec: {
      containerName: 'mlops_training_producer',
      baseImage: 'python:3.11-slim',
      user: 'UID: 1000 (Non-root)',
      capabilities: ['cap_drop: ALL'],
      noNewPrivileges: true,
      mountedVolumes: [
        { hostPath: './data_storage', containerPath: '/app/data_storage', mode: 'ro' },
        { hostPath: './artifacts', containerPath: '/app/artifacts', mode: 'rw' },
        { hostPath: './keys', containerPath: '/app/keys', mode: 'rw' }
      ],
      keyStatus: {
        hasPrivateKey: true,
        hasPublicKey: true,
        note: 'Custodisce la chiave privata RSA (private_key.pem) per la firma degli artefatti approvati.'
      }
    },
    codeSnippet: `# pipeline/crypto_signer.py
signer = ModelProducerSigner(private_key_path="keys/private_key.pem")
signature = signer.sign_artifact(
    artifact_path=Path("artifacts/clean_model.pkl"),
    signature_output_path=Path("artifacts/clean_model.pkl.sig")
)`
  },
  {
    id: 'registry',
    title: 'Model Registry & Storage',
    subtitle: 'MLflow Tracking Server & Local Artifact Store',
    domain: 'Storage & Staging Boundary (Untrusted)',
    defaultPosition: { x: 310, y: 70 },
    description: 'Registro centralizzato MLflow (sqlite backend store + artifact root locale su filesystem). Conserva versioni di modello, metadati e directory di pacchetto. Se non protetto, è il target primario di supply chain tampering.',
    pythonFile: 'mlflow server (--backend-store-uri sqlite:///... --default-artifact-root /app/artifacts)',
    dockerSpec: {
      containerName: 'mlops_tracking_server',
      baseImage: 'Dockerfile (python:3.11-slim)',
      user: 'UID: 1000',
      capabilities: ['cap_drop: ALL'],
      noNewPrivileges: true,
      mountedVolumes: [
        { hostPath: './data_storage', containerPath: '/app/data_storage', mode: 'rw' },
        { hostPath: './artifacts', containerPath: '/app/artifacts', mode: 'rw' }
      ],
      keyStatus: {
        hasPrivateKey: false,
        hasPublicKey: false,
        note: 'Conservazione agnostica degli artefatti binari; nessuna gestione crittografica interna.'
      }
    },
    codeSnippet: `# MLflow Model Registry URI:
# models:/fraud_detector/1 (oppure runs:/<run_id>/model)
# Artifact path: /app/artifacts/mlflow_registry/model/
#
# Scenario di manomissione supply chain:
# Un attaccante con accesso al canale di staging o filesystem sostituisce
# model.statsmodels o altera MLmodel con un payload __reduce__.`
  },
  {
    id: 'gate',
    title: 'Security Gate',
    subtitle: 'Admission Controller & Crypto Verifier',
    domain: 'Policy Enforcement Point (Zero-Trust)',
    defaultPosition: { x: 570, y: 150 },
    description: 'Cancello di sicurezza intermedio prima dell\'ammissione al runtime di inferenza. Valida la firma digitale con RSA-PSS SHA-256 e impedisce il caricamento in caso di firma mancante o alterata.',
    pythonFile: 'pipeline/crypto_signer.py (ModelConsumerVerifier)',
    dockerSpec: {
      containerName: 'mlops_security_gate',
      baseImage: 'python:3.11-slim',
      user: 'UID: 1000 (Non-root)',
      capabilities: ['cap_drop: ALL'],
      noNewPrivileges: true,
      mountedVolumes: [
        { hostPath: './keys/public_key.pem', containerPath: '/app/keys/public_key.pem', mode: 'ro' },
        { hostPath: './artifacts', containerPath: '/app/artifacts', mode: 'ro' }
      ],
      keyStatus: {
        hasPrivateKey: false,
        hasPublicKey: true,
        note: 'Monta ESCLUSIVAMENTE la chiave pubblica RSA in sola lettura (:ro). Minimo privilegio.'
      }
    },
    codeSnippet: `# pipeline/crypto_signer.py
def verify_model_integrity(model_bytes: bytes, sig_bytes: bytes, pub_key) -> bool:
    pub_key.verify(
        sig_bytes,
        model_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    # Se la firma non corrisponde, solleva SecurityError ed evita unpickling`
  },
  {
    id: 'consumer',
    title: 'Inference Consumer',
    subtitle: 'FastAPI Serving Worker (:8000)',
    domain: 'Unprivileged Production Serving (127.0.0.1)',
    defaultPosition: { x: 830, y: 80 },
    description: 'Servizio HTTP di produzione che espone gli endpoint /predict e /health. Se carica un artefatto MLflow/Pickle non verificato, il processo host viene compromesso durante la deserializzazione.',
    pythonFile: 'pipeline/serve.py (FraudInferenceService)',
    dockerSpec: {
      containerName: 'mlops_inference_consumer',
      baseImage: 'python:3.11-slim',
      user: 'UID: 1000 (Non-root)',
      capabilities: ['cap_drop: ALL'],
      noNewPrivileges: true,
      mountedVolumes: [
        { hostPath: './artifacts', containerPath: '/app/artifacts', mode: 'ro' },
        { hostPath: './keys/public_key.pem', containerPath: '/app/keys/public_key.pem', mode: 'ro' }
      ],
      keyStatus: {
        hasPrivateKey: false,
        hasPublicKey: true,
        note: 'Segregazione rigida: la chiave privata NON è presente nel filesystem del container.'
      }
    },
    codeSnippet: `# pipeline/serve.py (FastAPI Consumer)
# Se MLFLOW_ALLOW_PICKLE_DESERIALIZATION=true senza verifica crittografica:
loaded_model = mlflow.statsmodels.load_model(model_uri) # <-- TRIGGER RCE

# Se protetto da Security Gate:
verifier.verify_artifact(artifact_path, signature_path) # <-- BLOCCO PREVENTIVO`
  },
  {
    id: 'audit',
    title: 'Forensic Audit Engine',
    subtitle: 'Runtime Execution Sentry',
    domain: 'Security Evidence & Telemetry',
    defaultPosition: { x: 1090, y: 140 },
    description: 'Modulo di osservazione e raccolta prove empiriche. Monitora la scrittura della traccia di audit in-process generata durante la ricostruzione dell\'oggetto nella Pickle Virtual Machine.',
    pythonFile: 'pipeline/payload_generator.py',
    dockerSpec: {
      containerName: 'mlops_audit_sentry',
      baseImage: 'python:3.11-slim',
      user: 'UID: 1000',
      capabilities: ['cap_drop: ALL'],
      noNewPrivileges: true,
      mountedVolumes: [
        { hostPath: './reports', containerPath: '/app/reports', mode: 'rw' }
      ],
      keyStatus: {
        hasPrivateKey: false,
        hasPublicKey: false,
        note: 'Monitora la comparsa della traccia deserialization_audit_proof.log.'
      }
    },
    codeSnippet: `# UniversalPolyglotTrojan (__reduce__ protocol)
def __reduce__(self):
    expr = (
        f'(open("reports/audit.log", "w").write('
        f'f"[AUDIT] Worker PID: {__import__(\\'os\\').getpid()}\\\\n"), '
        f'__import__("pickle").loads(clean_model_bytes))[1]'
    )
    return (builtins.eval, (expr,)) # Esecuzione in-process durante REDUCE`
  }
];

export const PICKLE_BYTECODE_SAMPLE = ` 0: \\x80 PROTO      4
 2: \\x95 FRAME      72
11: \\x8c SHORT_BINUNICODE 'builtins'
21: \\x8c SHORT_BINUNICODE 'eval'
27: \\x93 STACK_GLOBAL
35: \\x8c SHORT_BINUNICODE '(open("reports/audit.log", "w").write(...), pickle.loads(...))[1]'
95: \\x85 TUPLE1
96: R    REDUCE    <=== [ARBITRARY CODE EXECUTION TRIGGERED IN-PROCESS]
97: .    STOP`;
