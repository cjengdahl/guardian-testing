import pickle
import yaml
import xml.etree.ElementTree as ET

# CWE-502: Deserialization of Untrusted Data
# CWE-611: Improper Restriction of XML External Entity Reference (XXE)


def load_session(session_bytes):
    """Restore a user session from serialized bytes."""
    # CWE-502: Deserializing user-supplied pickle data
    return pickle.loads(session_bytes)


def save_session(session_obj):
    """Serialize a session object."""
    return pickle.dumps(session_obj)


def parse_config(yaml_string):
    """Parse application config from YAML."""
    # CWE-502: yaml.load without Loader allows arbitrary object construction
    return yaml.load(yaml_string, Loader=yaml.Loader)


def parse_xml_upload(xml_data):
    """Parse an XML file uploaded by the user."""
    # CWE-611: Default ElementTree parser resolves external entities
    tree = ET.fromstring(xml_data)
    return tree


if __name__ == "__main__":
    data = b'\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00.'
    session = load_session(data)

    cfg = parse_config("key: value")
    print(cfg)
