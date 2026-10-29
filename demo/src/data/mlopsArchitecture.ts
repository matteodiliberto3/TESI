import { MLOpsNode, ScenarioInfo } from '../types/mlops';

export const SCENARIOS: ScenarioInfo[] = [
  {
    id: 'baseline',
    name: 'Baseline Legittima'
  },
  {
    id: 'deserialization',
    name: 'Attacco Deserializzazione'
  },
  {
    id: 'crypto-defense',
    name: 'Difesa Crittografica'
  },
  {
    id: 'safe-format',
    name: 'Formato Sicuro'
  }
];

export const MLOPS_NODES: MLOpsNode[] = [
  {
    id: 'producer',
    title: 'Training Producer',
    subtitle: 'CI/CD Build & Signing Pipeline',
    domain: 'Authorized Build Domain (SLSA L3)',
    defaultPosition: { x: 50, y: 130 },
    description: 'Ambiente di build containerizzato responsabile dell\'addestramento del modello RandomForest su Scikit-Learn e della generazione della firma crittografica RSA-PSS.',
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
model_bytes = pickle.dumps(trained_model)
signature = signer.sign_bytes(model_bytes)

with open("artifacts/model.pkl", "wb") as f:
    f.write(model_bytes)
with open("artifacts/model.pkl.sig", "wb") as f:
    f.write(signature)`
  },
  {
    id: 'registry',
    title: 'Model Registry & Storage',
    subtitle: 'MLflow Registry + MinIO S3',
    domain: 'Storage & Staging Boundary (Untrusted)',
    defaultPosition: { x: 310, y: 70 },
    description: 'Registro centralizzato degli artefatti ML. Archivia versioni di modello, metadati di training e oggetti serializzati (.pkl, .sig). Se non protetto, è il target primario di supply chain injection.',
    pythonFile: 'mlflow / minio s3 buckets',
    dockerSpec: {
      containerName: 'mlflow_minio_storage',
      baseImage: 'minio/minio:RELEASE.2024 + mlflow:v2.14',
      user: 'UID: 1000',
      capabilities: ['cap_drop: ALL'],
      noNewPrivileges: true,
      mountedVolumes: [
        { hostPath: './minio_data', containerPath: '/data', mode: 'rw' },
        { hostPath: './artifacts', containerPath: '/mlflow/artifacts', mode: 'rw' }
      ],
      keyStatus: {
        hasPrivateKey: false,
        hasPublicKey: false,
        note: 'Conservazione agnostica degli artefatti binari; nessuna gestione crittografica interna.'
      }
    },
    codeSnippet: `# MLflow Model Staging URI
# s3://mlops-models/fraud-detection/v2/model.pkl
# Checksum SHA-256 originale: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

# Iniezione artefatto non attendibile nel bucket:
# Sostituzione di model.pkl con trojan polyglot senza aggiornare la firma valida`
  },
  {
    id: 'gate',
    title: 'Security Gate',
    subtitle: 'Admission Controller & Crypto Verifier',
    domain: 'Policy Enforcement Point (Zero-Trust)',
    defaultPosition: { x: 570, y: 150 },
    description: 'Cancello di sicurezza intermedio prima dell\'ammissione del modello al runtime di inferenza. Valida la firma digitale con RSA-PSS SHA-256 e impedisce il caricamento in caso di firma mancante o non valida.',
    pythonFile: 'pipeline/crypto_signer.py (ModelConsumerVerifier)',
    dockerSpec: {
      containerName: 'admission_security_gate',
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
    # Se la firma fallisce, solleva SecurityError ed evita unpickling`
  },
  {
    id: 'consumer',
    title: 'Inference Consumer',
    subtitle: 'FastAPI Serving Worker (:8000)',
    domain: 'Unprivileged Production Serving',
    defaultPosition: { x: 830, y: 80 },
    description: 'Servizio HTTP di produzione che espone gli endpoint /predict e /health. Se carica un artefatto Pickle non verificato, la sua memoria e il processo host vengono compromessi durante l\'invocazione di pickle.load().',
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
    codeSnippet: `# pipeline/serve.py
class FraudInferenceService:
    def __init__(self, mode="vulnerable_pickle"):
        if mode == "vulnerable_pickle":
            # CRITICAL FAILURE POINT:
            with open("artifacts/model.pkl", "rb") as f:
                self.model = pickle.load(f) # <-- TRIGGER RCE
        elif mode == "signed_pickle":
            self.model = self.verifier.load_verified_pickle(...)`
  },
  {
    id: 'audit',
    title: 'Forensic Audit Engine',
    subtitle: 'Runtime Execution Sentry',
    domain: 'Security Evidence & Telemetry',
    defaultPosition: { x: 1090, y: 140 },
    description: 'Modulo di osservazione e raccolta prove scientifiche. Monitora la scrittura della traccia di audit generata durante la ricostruzione dell\'oggetto nella Pickle Virtual Machine.',
    pythonFile: 'experiments/exp1_deserialization.py',
    dockerSpec: {
      containerName: 'audit_sentry_watcher',
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
        note: 'Monitora la comparsa del file deserialization_audit_proof.log.'
      }
    },
    codeSnippet: `# PolyglotTrojanWrapper (__reduce__ opcode)
def __reduce__(self):
    cmd = (
        'python -c "import time, os; '
        'open(\\'reports/audit_proof.log\\', \\'w\\').write('
        'f\\'[AUDIT PROOF] Executed in worker PID: {os.getpid()} at {time.time()}\\\\n\\')"'
    )
    return (os.system, (cmd,)) # Callable eseguito durante REDUCE`
  }
];

export const PICKLE_BYTECODE_SAMPLE = ` 0: \\x80 PROTO      4
 2: \\x95 FRAME      68
11: \\x8c SHORT_BINUNICODE 'os'
15: \\x8c SHORT_BINUNICODE 'system'
23: \\x93 STACK_GLOBAL
32: \\x8c SHORT_BINUNICODE 'python -c "open(\\'reports/audit.log\\', \\'w\\').write(...)"'
80: \\x85 TUPLE1
81: R    REDUCE    <=== [ARBITRARY CODE EXECUTION TRIGGERED AT THIS OP]
82: .    STOP`;
