import yaml, json
from jinja2 import Template
from app.cloud_actions import aws_actions  # Changed from azure_actions

# Updated ACTION_MAP to use AWS actions
ACTION_MAP = {
    "isolate_vm": aws_actions.isolate_vm,
    "snapshot_disk": aws_actions.snapshot_disk,
    "revoke_user_access": aws_actions.revoke_user_access
}

def load_playbook(path):
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def load_incident(path):
    with open(path, 'r') as f:
        return json.load(f)

def render_param(template_str, context):
    return Template(template_str).render(incident=context)

def run_playbook(playbook_path, incident):
    playbook = load_playbook(playbook_path)
    steps = playbook['steps']
    
    for step in steps:
        action = step['action']
        params = {
            key: render_param(value, {"incident": incident})
            for key, value in step['parameters'].items()
        }
        
        func = ACTION_MAP.get(action)
        if func:
            print(f"[INFO] Executing action: {action} with params: {params}")
            func(**params)
        else:
            print(f"[ERROR] Unknown action: {action}")
