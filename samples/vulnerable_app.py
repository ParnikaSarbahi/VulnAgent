"""
vulnerable_app.py

Intentionally vulnerable sample file used to test Bandit SAST scanning.
DO NOT use these patterns in real code — each one below is a deliberately
planted security flaw so VulnAgent has real findings to triage.
"""

import subprocess
import hashlib
import pickle
import os


def run_user_command(user_input):
    # B602 / B605: shell=True with untrusted input enables shell injection
    subprocess.call(user_input, shell=True)


def hash_password(password):
    # B303: MD5 is a broken hash, unsafe for passwords
    return hashlib.md5(password.encode()).hexdigest()


def load_data(file_path):
    # B301: pickle.load on untrusted input allows arbitrary code execution
    with open(file_path, "rb") as f:
        return pickle.load(f)


def connect_to_db():
    # B105: hardcoded password/credential
    password = "SuperSecret123"
    return password


def run_query(user_id):
    # B608: SQL built via string formatting -> SQL injection
    query = "SELECT * FROM users WHERE id = '%s'" % user_id
    return query


def get_temp_file():
    # B108: hardcoded /tmp path, predictable and insecure
    return "/tmp/vulnagent_temp_file"


def debug_mode_check():
    # B105-style / general bad practice: leftover debug flag
    DEBUG = True
    if DEBUG:
        os.system("echo debug mode is on")  # B605/B607: os.system with partial path