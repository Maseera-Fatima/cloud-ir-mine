from app.engine.playbook_runner import run_playbook, load_incident

# Load incident data (same structure, different cloud details)
incident = load_incident("app/incidents/sample_incident.json")

# Run AWS-specific playbook instead of Azure
run_playbook("app/playbooks/aws-unauthorized-ec2-login.yml", incident)
