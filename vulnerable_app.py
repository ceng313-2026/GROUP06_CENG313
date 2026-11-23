"""Intentionally vulnerable examples for a local classroom demonstration."""
import pickle
import ssl
import subprocess
import tempfile
import yaml


def run_report():
    user_expression = input("Expression: ")
    # CWE-95: untrusted input is evaluated as Python code.
    result = eval(user_expression)
    return result


def search_users(cursor):
    username = input("Username: ")
    # CWE-89: user input is inserted into SQL syntax.
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")


def run_tool():
    filename = input("File: ")
    # CWE-78: untrusted input is interpreted by a shell.
    subprocess.run("cat " + filename, shell=True)


def load_session(upload):
    # CWE-502: pickle should not deserialize untrusted uploads.
    return pickle.loads(upload.read())


def read_document(name):
    # CWE-22 candidate: user input is incorporated into a filesystem path.
    return open("/srv/documents/" + name, encoding="utf-8").read()


def load_configuration(untrusted_text):
    # CWE-502: explicitly unsafe YAML deserialization.
    return yaml.load(untrusted_text, Loader=yaml.Loader)


def open_unverified_tls_context():
    # CWE-295: peer certificate verification is disabled.
    return ssl._create_unverified_context()


def create_temporary_path():
    # CWE-367: another process can race the later file creation.
    return tempfile.mktemp()


api_key = "demo-secret-key-123456"
