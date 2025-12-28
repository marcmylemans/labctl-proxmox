
#!/usr/bin/env python3
import os, sys, time, argparse
from pathlib import Path
import yaml
import winrm
from proxmoxer import ProxmoxAPI

def env(name, default=None, required=False):
    v = os.getenv(name, default)
    if required and not v:
        raise RuntimeError(f"Missing env var {name}")
    return v

PVE_HOST = env("PVE_HOST", required=True)
PVE_USER = env("PVE_USER", required=True)
PVE_TOKEN_NAME = env("PVE_TOKEN_NAME", required=True)
PVE_TOKEN_VALUE = env("PVE_TOKEN_VALUE", required=True)
PVE_REALM = env("PVE_REALM", "pam")
PVE_VERIFY_SSL = env("PVE_VERIFY_SSL", "true").lower() not in ("false","0")

def proxmox():
    return ProxmoxAPI(
        PVE_HOST,
        user=f"{PVE_USER}@{PVE_REALM}!{PVE_TOKEN_NAME}",
        token_name=PVE_TOKEN_NAME,
        token_value=PVE_TOKEN_VALUE,
        verify_ssl=PVE_VERIFY_SSL
    )

def load_lab(path):
    return yaml.safe_load(Path(path).read_text())

def wait_task(p, node, upid):
    while True:
        t = p.nodes(node).tasks(upid).status.get()
        if t["status"] == "stopped":
            if t.get("exitstatus") not in (None, "OK"):
                raise RuntimeError(t)
            return
        time.sleep(2)

def winrm_run(lab, host, script):
    w = lab["winrm"]
    sess = winrm.Session(
        f"http://{host}:{w.get('port',5985)}/wsman",
        auth=(w["username"], w["password"]),
        transport=w.get("transport","ntlm")
    )
    r = sess.run_ps(script)
    if r.status_code != 0:
        raise RuntimeError(r.std_err.decode())
    print(r.std_out.decode())

def create(labfile, apply_break):
    lab = load_lab(labfile)
    p = proxmox()
    node = lab["proxmox"]["node"]

    for name, vm in lab["vms"].items():
        upid = p.nodes(node).qemu(vm["template"]).clone.post(
            newid=vm["vmid"],
            name=vm["name"],
            full=1
        )
        wait_task(p, node, upid)
        wait_task(p, node, p.nodes(node).qemu(vm["vmid"]).status.start.post())

    time.sleep(30)

    if apply_break:
        target = lab["break"]["target"]
        script = Path(labfile).parent / lab["break"]["script"]
        winrm_run(lab, lab["vms"][target]["ip"], script.read_text())

def destroy(labfile):
    lab = load_lab(labfile)
    p = proxmox()
    node = lab["proxmox"]["node"]
    for vm in lab["vms"].values():
        try:
            p.nodes(node).qemu(vm["vmid"]).status.stop.post()
            time.sleep(5)
            p.nodes(node).qemu(vm["vmid"]).delete()
        except:
            pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["create","destroy"])
    ap.add_argument("lab")
    ap.add_argument("--apply-break", action="store_true")
    a = ap.parse_args()

    if a.cmd == "create":
        create(a.lab, a.apply_break)
    else:
        destroy(a.lab)

if __name__ == "__main__":
    main()
