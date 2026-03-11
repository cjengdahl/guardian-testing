import pickle
import yaml
import json

# CWE-502: Deserialization of Untrusted Data
# CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes


def load_session(session_data: bytes):
    """Restore a user session from serialized bytes."""
    # CWE-502: Deserializing untrusted pickle data — arbitrary code execution
    return pickle.loads(session_data)


def load_config(yaml_str: str):
    """Load application config from a YAML string."""
    # CWE-502: yaml.load without Loader allows arbitrary Python object instantiation
    return yaml.load(yaml_str, Loader=yaml.Loader)


def update_user_profile(user_obj, updates: dict):
    """Apply a dict of updates directly onto a user object."""
    # CWE-915: Caller controls which attributes are set, including __class__, __dict__, etc.
    for key, value in updates.items():
        setattr(user_obj, key, value)
    return user_obj


class User:
    def __init__(self, username, role="viewer"):
        self.username = username
        self.role = role


def load_user_from_request(json_body: str):
    """Deserialize a user object from a JSON request body."""
    data = json.loads(json_body)
    user = User.__new__(User)
    # CWE-502 / CWE-915: Blindly updating object state from untrusted input
    user.__dict__.update(data)
    return user


if __name__ == "__main__":
    raw = b'\x80\x04\x95...'  # attacker-controlled pickle payload
    session = load_session(raw)

    cfg = load_config("!!python/object/apply:os.system ['id']")
    print(cfg)

    u = User("alice")
    update_user_profile(u, {"role": "admin", "__class__": "evil"})
    print(u.role)
