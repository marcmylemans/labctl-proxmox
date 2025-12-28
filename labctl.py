#!/usr/bin/env python3
"""
labctl.py — Proxmox lab controller (with auto-cleanup + env injection)

Requirements:
  pip install proxmoxer pyyaml pywinrm python-dotenv
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

import yaml
import winrm
from dotenv import load_dotenv
from proxmoxer import ProxmoxAPI

# -----------------------------
# ENV
# -----------------------------
load_dotenv()

def env_str(name: str, default=None, required=False) -> str:
    v = os.getenv(name, default)
    if required and not v:
        raise RuntimeError(f"Missing env var: {name}")
    return str(v)

def env_bool(name: str, default=True) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() not in ("0", "false", "no", "off")

PVE_HOST        = env_str("PVE_HOST", required=True)
PVE_USER        = env_str("PVE_USER", required=True)
PVE_REALM       = env_str("PVE_REALM", "pam")
PVE_TOKEN_NAME  = env_str("PVE_TOKEN_NAME", required=True)
PVE_TOKEN_VALUE = env_str("PVE_TOKEN_VALUE", required=True)
PVE_VERIFY_SSL  = env_bool("PVE_VERIFY_SSL", True)

# -----------------------------
# PROXMOX
# -----------------------------
def proxmox() -> ProxmoxAPI:
    return ProxmoxAPI(
        PVE_HOST,
        user=f"{PVE_USER}@{PVE_REALM}",
        token_name=PVE_TOKEN_NAME,
        token_value=PVE_TOKEN_VALUE,
        verify_ssl=PVE_VERIFY_SSL,
    )

def wait_task(p, node, upid, timeout=900):
    start = time.time()
    while True:
        t = p.nodes(node).tasks(upid).status.get()
        if t["status"] == "stopped":
            if t.get("exitstatus") not in (None, "OK"):
                raise RuntimeError(f"Task failed: {t}")
            return
        if time.time() - start > timeout:
            raise TimeoutError("Proxmox task timeout")
        time.sleep(2)

def vm_exists(p, node, vmid) -> bool:
    try:
        p.nodes(node).qemu(vmid).status.current.get()
        return True
    except Exception:
        return False

# -----------------------------
# YAML
# -----------------------------
def load_lab(path: Path) -> Dict[str, Any]:
    lab = yaml.safe_load(path.read_text(encoding="utf-8"))
    if "proxmox" not in lab or "vms" not in lab:
        raise RuntimeError("Invalid lab.yaml (missing proxmox/vms)")
    if "winrm" not in lab:
        raise RuntimeError("Invalid lab.yaml (missing winrm)")
    return lab

def read_script(base: Path, rel: str) -> str:
    p = (base.parent / rel).resolve()
    if not p.exists():
        raise FileNotFoundError(p)
    return p.read_text(encoding="utf-8")

def sanitize_tag(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-._" else "-" for c in str(s)).strip("-") or "lab"

# -----------------------------
# LAB ENV (inject to scripts)
# -----------------------------
def lab_env(lab: Dict[str, Any], vmname: str) -> Dict[str, str]:
    """
    Build environment variables for bootstrap/break scripts.
    Reads from lab.yaml 'lab:' section.
    """
    cfg = lab.get("lab", {}) or {}
    env: Dict[str, str] = {}

    # Domain (optional - scripts have defaults)
    if "domain_fqdn" in cfg:
        env["LAB_DOMAIN_FQDN"] = str(cfg["domain_fqdn"])
    if "domain_netbios" in cfg:
        env["LAB_DOMAIN_NETBIOS"] = str(cfg["domain_netbios"])

    # Network
    if "prefix" in cfg:
        env["LAB_PREFIX"] = str(cfg["prefix"])
    if "gateway" in cfg:
        env["LAB_GW"] = str(cfg["gateway"])

    # DC IP (required by dc script)
    if "dc_ip" in cfg:
        env["LAB_DC_IP"] = str(cfg["dc_ip"])

    # Optional DSRM password
    if "dsrm_pass" in cfg:
        env["LAB_DSRM_PASS"] = str(cfg["dsrm_pass"])

    # DHCP (optional)
    dhcp = cfg.get("dhcp", {}) or {}
    if "scope_net" in dhcp:
        env["LAB_SCOPE_NET"] = str(dhcp["scope_net"])
    if "start" in dhcp:
        env["LAB_SCOPE_START"] = str(dhcp["start"])
    if "end" in dhcp:
        env["LAB_SCOPE_END"] = str(dhcp["end"])

    # Domain join creds (WS script requires JOIN_PASS)
    # For now we reuse the same password you already use everywhere.
    winrm_cfg = lab.get("winrm", {}) or {}
    if "password" in winrm_cfg:
        env["LAB_JOIN_PASS"] = str(winrm_cfg["password"])

    # Optional override join user (else WS script builds CORP\Administrator)
    if "join_user" in cfg:
        env["LAB_JOIN_USER"] = str(cfg["join_user"])

    # Per-VM
    env["LAB_VM_NAME"] = vmname

    return env

def _escape_for_cmd_set(value: str) -> str:
    """
    Escape characters that break CMD 'set "K=V" && ...' chains.
    """
    v = str(value)
    v = v.replace("^", "^^").replace("&", "^&").replace("<", "^<").replace(">", "^>")
    return v

# -----------------------------
# GUEST AGENT (IP)
# -----------------------------
def agent_call(p, node, vmid, cmd):
    return p.nodes(node).qemu(vmid).agent(cmd).get()

def flatten_ipv4(info):
    ips = []
    for iface in info.get("result", []):
        for a in iface.get("ip-addresses", []):
            if a.get("ip-address-type") == "ipv4":
                ip = a.get("ip-address")
                if ip and not ip.startswith(("127.", "169.254.")):
                    ips.append(ip)
    return ips

def wait_guest_agent(p, node, vmid):
    last = None
    for _ in range(80):
        try:
            info = agent_call(p, node, vmid, "network-get-interfaces")
            ips = flatten_ipv4(info)
            if ips:
                return ips
            last = "agent ok, no IP yet"
        except Exception as e:
            msg = str(e)
            if "501" in msg:
                raise RuntimeError("Guest agent endpoint disabled (qm set <id> --agent 1)")
            last = msg
        time.sleep(3)
    raise TimeoutError(f"Guest agent not ready: {last}")

def resolve_vm_ip(p, lab, vmname):
    vm = lab["vms"][vmname]
    if vm.get("ip"):
        return vm["ip"]
    node = lab["proxmox"]["node"]
    ips = wait_guest_agent(p, node, int(vm["vmid"]))
    preferred = lab.get("network", {}).get("prefer_ipv4_subnets", [])
    if preferred:
        nets = [ipaddress.ip_network(n, strict=False) for n in preferred]
        for ip in ips:
            if any(ipaddress.ip_address(ip) in n for n in nets):
                return ip
    return ips[0]

# -----------------------------
# WINRM (CMD ONLY)
# -----------------------------
def winrm_cfg(lab):
    w = lab["winrm"]
    return dict(
        username=w["username"],
        password=w["password"],
        transport=w.get("transport", "ntlm"),
        use_ssl=bool(w.get("use_ssl", False)),
        port=int(w.get("port", 5986 if w.get("use_ssl") else 5985)),
        server_cert_validation=w.get("server_cert_validation", "ignore"),
    )

def winrm_session(lab, host) -> winrm.Session:
    w = winrm_cfg(lab)
    scheme = "https" if w["use_ssl"] else "http"
    url = f"{scheme}://{host}:{w['port']}/wsman"
    return winrm.Session(
        url,
        auth=(w["username"], w["password"]),
        transport=w["transport"],
        server_cert_validation=w["server_cert_validation"],
    )

def wait_winrm(lab, host):
    last = None
    for _ in range(60):
        try:
            sess = winrm_session(lab, host)
            r = sess.run_cmd("cmd.exe", ["/c", "echo winrm-ok"])
            if r.status_code == 0:
                return
            last = (r.std_err or r.std_out or b"").decode(errors="replace")
        except Exception as e:
            last = str(e)
        time.sleep(5)
    raise TimeoutError(f"WinRM not reachable on {host}: {last}")

REMOTE_DIR  = r"C:\Windows\Temp\labctl"
CHUNK_BYTES = 12000

def upload_text_as_ps1(lab, host, text: str, remote_name: str) -> str:
    remote_ps1 = fr"{REMOTE_DIR}\{remote_name}"
    remote_b64 = fr"{remote_ps1}.b64"
    sess = winrm_session(lab, host)

    # prep
    for c in [
        f'mkdir "{REMOTE_DIR}"',
        f'del /f /q "{remote_b64}" 2>nul',
        f'del /f /q "{remote_ps1}" 2>nul',
    ]:
        r = sess.run_cmd("cmd.exe", ["/c", c])
        if r.status_code != 0:
            raise RuntimeError((r.std_err or b"").decode(errors="replace"))

    # upload base64
    b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
    for i in range(0, len(b64), CHUNK_BYTES):
        chunk = b64[i:i + CHUNK_BYTES]
        r = sess.run_cmd("cmd.exe", ["/c", f'echo {chunk}>>"{remote_b64}"'])
        if r.status_code != 0:
            raise RuntimeError((r.std_err or b"").decode(errors="replace"))

    # decode (no powershell, avoids WinRM 400/XML issues)
    r = sess.run_cmd("cmd.exe", ["/c", f'certutil -f -decode "{remote_b64}" "{remote_ps1}" >nul'])
    if r.status_code != 0:
        out = (r.std_out or b"").decode(errors="replace")
        err = (r.std_err or b"").decode(errors="replace")
        raise RuntimeError(f"certutil decode failed: {out}\n{err}")

    return remote_ps1

def exec_remote_ps1(lab, host, remote_ps1: str, env: Optional[Dict[str, str]] = None):
    """
    Execute a .ps1 remotely while injecting env vars via CMD.
    Avoids run_ps() entirely.
    """
    sess = winrm_session(lab, host)

    set_parts: List[str] = []
    if env:
        for k, v in env.items():
            set_parts.append(f'set "{k}={_escape_for_cmd_set(v)}"')

    ps_cmd = fr'powershell -NoProfile -ExecutionPolicy Bypass -File "{remote_ps1}"'
    full_cmd = " && ".join(set_parts + [ps_cmd]) if set_parts else ps_cmd

    r = sess.run_cmd("cmd.exe", ["/c", full_cmd])
    out = (r.std_out or b"").decode(errors="replace")
    err = (r.std_err or b"").decode(errors="replace")
    return int(r.status_code), out, err

# -----------------------------
# VM OPS
# -----------------------------
def clone_vm(p, node, template, vmid, name, tags):
    if vm_exists(p, node, vmid):
        raise RuntimeError(f"VMID {vmid} already exists")
    upid = p.nodes(node).qemu(template).clone.post(newid=vmid, name=name, full=1)
    wait_task(p, node, upid)
    p.nodes(node).qemu(vmid).config.post(tags=",".join(tags))

def start_vm(p, node, vmid):
    upid = p.nodes(node).qemu(vmid).status.start.post()
    wait_task(p, node, upid)

def stop_vm(p, node, vmid):
    try:
        upid = p.nodes(node).qemu(vmid).status.shutdown.post(timeout=60)
        wait_task(p, node, upid)
    except Exception:
        upid = p.nodes(node).qemu(vmid).status.stop.post()
        wait_task(p, node, upid)

def destroy_vm(p, node, vmid):
    upid = p.nodes(node).qemu(vmid).delete()
    wait_task(p, node, upid)

# -----------------------------
# ORDERING
# -----------------------------
def ordered_vms(lab):
    return sorted(lab["vms"].items(), key=lambda kv: 0 if kv[1].get("role") == "dc" else 1)

# -----------------------------
# BOOTSTRAP / BREAK
# -----------------------------
def bootstrap_vm(lab_path, lab, p, vmname):
    vm = lab["vms"][vmname]
    rel = vm.get("bootstrap")
    if not rel:
        return

    reboot_expected = bool(vm.get("reboot_expected", False))
    host = resolve_vm_ip(p, lab, vmname)
    print(f"Bootstrapping {vmname} at {host} using {rel}")

    wait_winrm(lab, host)
    text = read_script(lab_path, rel)
    remote_ps1 = upload_text_as_ps1(lab, host, text, f"{vmname}-bootstrap.ps1")

    env = lab_env(lab, vmname)

    try:
        code, out, err = exec_remote_ps1(lab, host, remote_ps1, env=env)
        if out.strip():
            print(out.strip())
        if code != 0:
            raise RuntimeError(err.strip() or out.strip())
    except Exception:
        if reboot_expected:
            print(f"⚠️  WinRM disconnected during bootstrap of {vmname} (expected)")
        else:
            raise

    if reboot_expected:
        time.sleep(30)
        wait_winrm(lab, host)

def apply_break(lab_path, lab, p):
    br = lab.get("break")
    if not br:
        return
    target = br["target"]
    rel = br["script"]
    host = resolve_vm_ip(p, lab, target)
    print(f"Applying break on {target} ({host})")
    wait_winrm(lab, host)
    text = read_script(lab_path, rel)
    remote_ps1 = upload_text_as_ps1(lab, host, text, f"{target}-break.ps1")

    env = lab_env(lab, target)

    code, out, err = exec_remote_ps1(lab, host, remote_ps1, env=env)
    if code != 0:
        raise RuntimeError(err or out)

# -----------------------------
# CLEANUP
# -----------------------------
def cleanup_run(p, created_vms: List[Tuple[str, int]]):
    print("🧹 Cleaning up created resources...")
    for node, vmid in reversed(created_vms):
        try:
            if vm_exists(p, node, vmid):
                stop_vm(p, node, vmid)
                destroy_vm(p, node, vmid)
        except Exception as e:
            print(f"Cleanup warning (vm {vmid}): {e}")

# -----------------------------
# COMMANDS
# -----------------------------
def cmd_create(args):
    lab_path = Path(args.lab_yaml)
    lab = load_lab(lab_path)
    p = proxmox()
    node = lab["proxmox"]["node"]

    run_id = sanitize_tag(args.run_id or str(int(time.time())))
    lab_id = sanitize_tag(lab.get("id", "lab"))
    tags = [f"lab-{lab_id}", f"run-{run_id}"]

    created_vms: List[Tuple[str, int]] = []

    try:
        # clone
        for name, vm in ordered_vms(lab):
            print(f"Cloning {name}")
            clone_vm(p, node, int(vm["template"]), int(vm["vmid"]), vm.get("name", name), tags)
            created_vms.append((node, int(vm["vmid"])))

        # start + bootstrap
        for name, vm in ordered_vms(lab):
            print(f"Starting {name}")
            start_vm(p, node, int(vm["vmid"]))
            time.sleep(15)
            bootstrap_vm(lab_path, lab, p, name)

        if args.apply_break:
            apply_break(lab_path, lab, p)

        print("✅ Lab created successfully")

    except Exception as e:
        print(f"❌ Lab creation failed: {e}")
        if args.auto_cleanup:
            cleanup_run(p, created_vms)
        else:
            print("⚠️ Auto-cleanup disabled; resources left intact")
        raise

def cmd_destroy(args):
    lab = load_lab(Path(args.lab_yaml))
    p = proxmox()
    node = lab["proxmox"]["node"]
    for name, vm in ordered_vms(lab):
        vmid = int(vm["vmid"])
        if vm_exists(p, node, vmid):
            stop_vm(p, node, vmid)
            destroy_vm(p, node, vmid)
    print("🗑️ Lab destroyed")

# -----------------------------
# CLI
# -----------------------------
def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create")
    c.add_argument("lab_yaml")
    c.add_argument("--run-id")
    c.add_argument("--apply-break", action="store_true")
    c.add_argument("--no-cleanup", dest="auto_cleanup", action="store_false")
    c.set_defaults(func=cmd_create, auto_cleanup=True)

    d = sub.add_parser("destroy")
    d.add_argument("lab_yaml")
    d.set_defaults(func=cmd_destroy)

    args = ap.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
