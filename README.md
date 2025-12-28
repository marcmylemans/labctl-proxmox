
# labctl-proxmox

Minimal Proxmox lab automation with real WinRM break injection.

## Install
pip install proxmoxer pywinrm pyyaml

## Env vars
PVE_HOST, PVE_USER, PVE_TOKEN_NAME, PVE_TOKEN_VALUE

## Run
./labctl.py create labs/lab-001/lab.yaml --apply-break
./labctl.py destroy labs/lab-001/lab.yaml
