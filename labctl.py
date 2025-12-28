#!/usr/bin/env python3
"""
labctl.py — Proxmox lab controller (YAML-driven) with:
- Proxmox API token auth via proxmoxer (supports .env via python-dotenv)
- VM clone/start/destroy
- QEMU Guest Agent IPv4 discovery (so lab.yaml doesn't need hardcoded IPs)
- WinRM execution for:
    - per-VM bootstrap (DC promote / domain join)
    - per-lab break scripts

Requires:
  pip install proxmoxer pyyaml pywinrm python-dotenv
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
import winrm
from dotenv import load_dotenv
from proxmoxer import ProxmoxAPI

# Load .env from CWD (recommended: run labctl from repo root)
load_dotenv()


# -----------------------------
# Env helpers
# -----------------------------

def env_str(name: str, default: Optional[str] = None, required: bool = False) -> str:
    v = os.getenv(name, default)
    if required and (v is None or str(v).strip() == ""):
        raise RuntimeError(f"Missing env var: {name}")
    return str(v) if v is not None else ""


def env_bool(name: str, default: bool = True) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() not in ("0", "false", "no", "off")


PVE_HOST = env_str("PVE_HOST", required=True)
PVE_USER = env_str("PVE_USER", required=True)
PVE_REALM = env_str("PVE_REALM", "pam")
PVE_TOKEN_NAME = env_str("PVE_TOKEN_NAME", required=True)
PVE_TOKEN_VALUE = env_str("PVE_TOKEN_VALUE", required=True)
PVE_VERIFY_SSL = env_bool("PVE_VERIFY_SSL", True)


# -----------------------------
# Proxmox connect / task wait
# -----------------------------

def proxmox() -> ProxmoxAPI:
    return ProxmoxAPI(
        PVE_HOST,
        user=f"{PVE_USER}@{PVE_REALM}",
        token_name=PVE_TOKEN_NAME,
        token_value=PVE_TOKEN_VALUE,
        verify_ssl=PVE_VERIFY_SSL,
    )


def wait_task(p: ProxmoxAPI, node: str, upid: str, timeout_s: int = 900) -> None:
    start = time.time()
    while True:
        t = p.nodes(node).tasks(upid).status.get()
        if t.get("status") == "stopped":
            exitstatus = t.get("exitstatus")
            if exitstatus and exitstatus != "OK":
                raise RuntimeError(f"Task failed: {upid} exitstatus={exitstatus}")
            return
        if time.time() - start > timeout_s:
            raise TimeoutError(f"Task timeout after {timeout_s}s: {upid}")
        time.sleep(2)


def vm_exists(p: ProxmoxAPI, node: str, vmid: int) -> bool:
    try:
        _ = p.nodes(node).qemu(vmid).status.current.get()
        return True
    except Exception:
        return False


# -----------------------------
# Lab YAML
# -----------------------------

def load_lab(path: Path) -> Dict[str, Any]:
    lab = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(lab, dict):
        raise RuntimeError("Invalid lab.yaml (must be a YAML mapping)")
    for k in ("proxmox", "vms"):
        if k not in lab:
            raise RuntimeError(f"Invalid lab.yaml: missing '{k}'")
    if "node" not in lab["proxmox"]:
        raise RuntimeError("Invalid lab.yaml: proxmox.node required")
    return lab


def read_script_text(base_path: Path, rel_path: str) -> str:
    p = (base_path.parent / rel_path).resolve()
    if not p.exists():
        raise FileNotFoundError(f"Script not found: {p}")
    return p.read_text(encoding="utf-8")


# -----------------------------
# Proxmox tag safety
# -----------------------------

def sanitize_tag(t: str) -> str:
    # Proxmox tag allowed chars: letters/digits and _ . -
    out = []
    for ch in str(t).strip():
        if ch.isalnum() or ch in ("_", "-", "."):
            out.append(ch)
        else:
            out.append("-")
    s = "".join(out).strip("-")
    return s or "tag"


# -----------------------------
# QEMU Guest Agent IPv4 discovery
# -----------------------------

def agent_call(p: ProxmoxAPI, node: str, vmid: int, cmd: str) -> Dict[str, Any]:
    return p.nodes(node).qemu(vmid).agent(cmd).get()


def wait_guest_agent(p: ProxmoxAPI, node: str, vmid: int, retries: int = 60, delay_s: int = 3) -> None:
    last = None
    for _ in range(retries):
        try:
            _ = p.nodes(node).qemu(vmid).agent("ping").get()
            return
        except Exception as e:
            last = str(e)
            time.sleep(delay_s)
    raise TimeoutError(f"Guest agent not ready (vmid={vmid} node={node}). Last error: {last}")


def flatten_ipv4_from_agent(netinfo: Dict[str, Any]) -> List[str]:
    ips: List[str] = []
    for iface in netinfo.get("result", []):
        for addr in iface.get("ip-addresses", []):
            if addr.get("ip-address-type") == "ipv4":
                ip = addr.get("ip-address")
                if not ip:
                    continue
                if ip.startswith("127.") or ip.startswith("169.254."):
                    continue
                ips.append(ip)
    return ips


def pick_best_ip(ips: List[str], preferred_subnets: List[str]) -> str:
    if not ips:
        raise RuntimeError("Guest agent returned no usable IPv4 addresses.")
    if preferred_subnets:
        nets = [ipaddress.ip_network(s, strict=False) for s in preferred_subnets]
        for ip in ips:
            ip_obj = ipaddress.ip_address(ip)
            if any(ip_obj in n for n in nets):
                return ip
    return ips[0]


def resolve_vm_ipv4(p: ProxmoxAPI, node: str, vmid: int, preferred_subnets: List[str]) -> str:
    wait_guest_agent(p, node, vmid)
    netinfo = agent_call(p, node, vmid, "network-get-interfaces")
    ips = flatten_ipv4_from_agent(netinfo)
    return pick_best_ip(ips, preferred_subnets)


def get_target_host(p: ProxmoxAPI, lab: Dict[str, Any], vm_name: str) -> str:
    node = str(lab["proxmox"]["node"])
    vms = lab["vms"]
    if vm_name not in vms:
        raise RuntimeError(f"VM '{vm_name}' not found in lab.vms")

    vm = vms[vm_name]
    # Backward compatible: if ip is provided, use it.
    if vm.get("ip"):
        return str(vm["ip"])

    preferred = (lab.get("network") or {}).get("prefer_ipv4_subnets", [])
    return resolve_vm_ipv4(p, node, int(vm["vmid"]), preferred)


# -----------------------------
# WinRM execution
# -----------------------------

def winrm_cfg(lab: Dict[str, Any]) -> Dict[str, Any]:
    w = lab.get("winrm") or {}
    for k in ("username", "password"):
        if not w.get(k):
            raise RuntimeError(f"lab.yaml missing winrm.{k}")
    return {
        "username": w["username"],
        "password": w["password"],
        "transport": w.get("transport", "ntlm"),
        "use_ssl": bool(w.get("use_ssl", False)),
        "port": int(w.get("port", 5986 if w.get("use_ssl") else 5985)),
        "server_cert_validation": w.get("server_cert_validation", "ignore"),
    }


def run_ps_winrm(lab: Dict[str, Any], host: str, ps_script: str, timeout_s: int = 120) -> Tuple[int, str, str]:
    w = winrm_cfg(lab)
    scheme = "https" if w["use_ssl"] else "http"
    endpoint = f"{scheme}://{host}:{w['port']}/wsman"

    sess = winrm.Session(
        target=endpoint,
        auth=(w["username"], w["password"]),
        transport=w["transport"],
        server_cert_validation=w["server_cert_validation"],
    )
    r = sess.run_ps(ps_script, timeout=timeout_s)

    stdout = (r.std_out or b"").decode(errors="replace").strip()
    stderr = (r.std_err or b"").decode(errors="replace").strip()
    return int(r.status_code), stdout, stderr


def wait_winrm(lab: Dict[str, Any], host: str, retries: int = 50, delay_s: int = 5) -> None:
    probe = "Write-Output 'winrm-ok'"
    last = None
    for _ in range(retries):
        try:
            code, out, err = run_ps_winrm(lab, host, probe, timeout_s=20)
            if code == 0 and "winrm-ok" in out:
                return
            last = f"code={code} out={out} err={err}"
        except Exception as e:
            last = str(e)
        time.sleep(delay_s)
    raise TimeoutError(f"WinRM not reachable on {host}. Last error: {last}")


# -----------------------------
# VM operations
# -----------------------------

def clone_vm(
    p: ProxmoxAPI,
    node: str,
    template_id: int,
    vmid: int,
    name: str,
    full: bool = True,
    storage: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> None:
    if vm_exists(p, node, vmid):
        raise RuntimeError(f"VMID {vmid} already exists on node {node}")

    payload: Dict[str, Any] = {"newid": vmid, "name": name, "full": 1 if full else 0}
    if storage:
        payload["storage"] = storage

    upid = p.nodes(node).qemu(template_id).clone.post(**payload)
    wait_task(p, node, upid)

    if tags:
        upid = p.nodes(node).qemu(vmid).config.post(tags=",".join(tags))
        wait_task(p, node, upid)


def start_vm(p: ProxmoxAPI, node: str, vmid: int) -> None:
    upid = p.nodes(node).qemu(vmid).status.start.post()
    wait_task(p, node, upid)


def stop_vm(p: ProxmoxAPI, node: str, vmid: int) -> None:
    try:
        upid = p.nodes(node).qemu(vmid).status.shutdown.post(timeout=90)
        wait_task(p, node, upid, timeout_s=180)
    except Exception:
        upid = p.nodes(node).qemu(vmid).status.stop.post()
        wait_task(p, node, upid, timeout_s=180)


def destroy_vm(p: ProxmoxAPI, node: str, vmid: int) -> None:
    upid = p.nodes(node).qemu(vmid).delete()
    wait_task(p, node, upid)


# -----------------------------
# Lab orchestration helpers
# -----------------------------

def ordered_vms(lab: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Start order:
      1) role == 'dc'
      2) everything else
    """
    items = list(lab["vms"].items())
    return sorted(items, key=lambda kv: 0 if str(kv[1].get("role", "")).lower() == "dc" else 1)


def apply_bootstrap(lab_path: Path, lab: Dict[str, Any], p: ProxmoxAPI, vm_name: str) -> None:
    vm = lab["vms"][vm_name]
    script_rel = vm.get("bootstrap")
    if not script_rel:
        print(f"No bootstrap defined for {vm_name}, skipping.")
        return

    host = get_target_host(p, lab, vm_name)
    print(f"Bootstrapping {vm_name} at {host} using {script_rel}")

    wait_winrm(lab, host)

    ps = read_script_text(lab_path, script_rel)
    code, out, err = run_ps_winrm(lab, host, ps, timeout_s=900)

    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)
    if code != 0:
        raise RuntimeError(f"Bootstrap failed on {vm_name} (host={host}) exit={code}")

    print(f"✅ Bootstrap complete for {vm_name}")


def wait_for_domain_ready(lab: Dict[str, Any], p: ProxmoxAPI, dc_vm_name: str, timeout_s: int = 900) -> None:
    """
    Wait until AD is ready on the DC (Get-ADDomain succeeds).
    Assumes ActiveDirectory module will exist after DC promotion.
    """
    host = get_target_host(p, lab, dc_vm_name)
    print(f"Waiting for domain readiness on {dc_vm_name} ({host}) ...")

    script = r"""
    try {
      Import-Module ActiveDirectory
      Get-ADDomain | Out-Null
      Write-Output "AD_READY"
      exit 0
    } catch {
      exit 1
    }
    """

    start = time.time()
    last = None
    while time.time() - start < timeout_s:
        try:
            code, out, err = run_ps_winrm(lab, host, script, timeout_s=30)
            if code == 0 and "AD_READY" in out:
                print("✅ AD is ready.")
                return
            last = f"code={code} out={out} err={err}"
        except Exception as e:
            last = str(e)
        time.sleep(10)

    raise TimeoutError(f"AD did not become ready within {timeout_s}s. Last: {last}")


# -----------------------------
# Break application
# -----------------------------

def apply_break(lab_path: Path, lab: Dict[str, Any], p: ProxmoxAPI) -> None:
    brk = lab.get("break")
    if not brk:
        print("No break section; nothing to apply.")
        return

    target = brk.get("target")
    script_rel = brk.get("script")
    if not target or not script_rel:
        raise RuntimeError("break.target and break.script are required in lab.yaml")

    host = get_target_host(p, lab, target)
    print(f"Discovered break target '{target}' at {host}")

    wait_winrm(lab, host)

    ps = read_script_text(lab_path, script_rel)
    print(f"Running break script: {script_rel}")
    code, out, err = run_ps_winrm(lab, host, ps, timeout_s=300)

    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)
    if code != 0:
        raise RuntimeError(f"Break script failed on {target} (host={host}) exit={code}")

    print("✅ Break applied.")


# -----------------------------
# Commands
# -----------------------------

def cmd_create(args: argparse.Namespace) -> None:
    lab_path = Path(args.lab_yaml)
    lab = load_lab(lab_path)
    p = proxmox()
    node = str(lab["proxmox"]["node"])

    run_id = args.run_id or str(int(time.time()))
    lab_id = sanitize_tag(lab.get("id", "lab"))
    run_id_safe = sanitize_tag(run_id)
    tags = [f"lab-{lab_id}", f"run-{run_id_safe}"]

    # Clone all VMs (in order, but cloning order doesn't matter much)
    for vm_key, vm in ordered_vms(lab):
        template = int(vm["template"])
        vmid = int(vm["vmid"])
        name = str(vm.get("name") or f"{lab_id}-{vm_key}")
        full = bool(vm.get("full_clone", True))
        storage = vm.get("storage")

        print(f"Cloning {vm_key}: template={template} -> vmid={vmid} name={name} node={node}")
        clone_vm(p, node, template, vmid, name, full=full, storage=storage, tags=tags)

    # Start + bootstrap in deterministic order
    dc_name: Optional[str] = None
    for vm_key, vm in ordered_vms(lab):
        if str(vm.get("role", "")).lower() == "dc":
            dc_name = vm_key
            break

    for vm_key, vm in ordered_vms(lab):
        vmid = int(vm["vmid"])
        print(f"Starting {vm_key} (vmid={vmid}) ...")
        start_vm(p, node, vmid)

        # Give it a moment before probing agent/winrm
        time.sleep(max(5, args.wait_seconds))

        # Apply bootstrap if configured
        apply_bootstrap(lab_path, lab, p, vm_key)

        # If we just bootstrapped the DC, wait until AD is ready before moving on
        if dc_name and vm_key == dc_name:
            wait_for_domain_ready(lab, p, dc_name, timeout_s=900)

    if args.apply_break:
        apply_break(lab_path, lab, p)

    print("✅ Create complete.")


def cmd_destroy(args: argparse.Namespace) -> None:
    lab = load_lab(Path(args.lab_yaml))
    p = proxmox()
    node = str(lab["proxmox"]["node"])

    # stop first
    for vm_key, vm in ordered_vms(lab):
        vmid = int(vm["vmid"])
        if not vm_exists(p, node, vmid):
            print(f"{vm_key} (vmid={vmid}) missing, skip stop.")
            continue
        print(f"Stopping {vm_key} (vmid={vmid}) ...")
        stop_vm(p, node, vmid)

    # destroy
    for vm_key, vm in ordered_vms(lab):
        vmid = int(vm["vmid"])
        if not vm_exists(p, node, vmid):
            print(f"{vm_key} (vmid={vmid}) missing, skip destroy.")
            continue
        print(f"Destroying {vm_key} (vmid={vmid}) ...")
        destroy_vm(p, node, vmid)

    print("🗑️ Destroy complete.")


def cmd_reset(args: argparse.Namespace) -> None:
    print("Reset strategy: destroy-and-rebuild")
    cmd_destroy(args)
    cmd_create(args)


def cmd_status(args: argparse.Namespace) -> None:
    lab = load_lab(Path(args.lab_yaml))
    p = proxmox()
    node = str(lab["proxmox"]["node"])
    title = lab.get("title", lab.get("id", "lab"))

    print(f"{title} ({lab.get('id','')})")
    for vm_key, vm in ordered_vms(lab):
        vmid = int(vm["vmid"])
        state = "missing"
        if vm_exists(p, node, vmid):
            cur = p.nodes(node).qemu(vmid).status.current.get()
            state = cur.get("status", "unknown")
        print(f"  {vm_key:6} vmid={vmid:<5} state={state}")


def cmd_break(args: argparse.Namespace) -> None:
    lab_path = Path(args.lab_yaml)
    lab = load_lab(lab_path)
    p = proxmox()
    apply_break(lab_path, lab, p)


# -----------------------------
# CLI
# -----------------------------

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="labctl", description="YAML-driven Proxmox lab controller")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("lab_yaml", help="Path to lab.yaml")
        sp.add_argument("--run-id", help="Optional run id for tagging")
        sp.add_argument(
            "--wait-seconds",
            type=int,
            default=15,
            help="Seconds to wait after VM start before probing agent/winrm (default: 15)",
        )
        sp.add_argument("--apply-break", action="store_true", help="Apply break after create/reset")

    sp = sub.add_parser("create", help="Clone + start + bootstrap lab VMs")
    add_common(sp)
    sp.set_defaults(func=cmd_create)

    sp = sub.add_parser("destroy", help="Stop + destroy lab VMs")
    add_common(sp)
    sp.set_defaults(func=cmd_destroy)

    sp = sub.add_parser("reset", help="Destroy and rebuild lab VMs")
    add_common(sp)
    sp.set_defaults(func=cmd_reset)

    sp = sub.add_parser("status", help="Show VM status")
    sp.add_argument("lab_yaml", help="Path to lab.yaml")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("break", help="Apply break only (no create)")
    sp.add_argument("lab_yaml", help="Path to lab.yaml")
    sp.set_defaults(func=cmd_break)

    return ap


def main() -> None:
    ap = build_parser()
    args = ap.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
