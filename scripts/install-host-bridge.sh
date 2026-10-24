#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BRIDGE_TEMPLATE="$ROOT/deploy/joe-mcp-host-bridge.service.in"
SESSION_TEMPLATE="$ROOT/deploy/joe-mcp-session-host.service.in"
RUNNER_TEMPLATE="$ROOT/deploy/joe-mcp-session-runner.in"
CLI_TEMPLATE="$ROOT/deploy/joe-cli.in"
WORKSPACE_TEMPLATE="$ROOT/config/workspaces.json"
DEPLOY_RUNNER_TEMPLATE="$ROOT/deploy/joe-mcp-controller-deploy-runner.in"
DEPLOY_SERVICE_TEMPLATE="$ROOT/deploy/joe-mcp-controller-deploy.service.in"
WORKSPACE_FILE="/var/lib/joe-mcp-work/workspaces.json"
BRIDGE_UNIT="/etc/systemd/system/joe-mcp-host-bridge.service"
SESSION_UNIT="/etc/systemd/system/joe-mcp-session-host.service"
DEPLOY_SERVICE_UNIT="/etc/systemd/system/joe-mcp-controller-deploy.service"
DEPLOY_RUNNER="/usr/local/libexec/joe-mcp-controller-deploy-runner.py"
WORKSPACE_DROPIN_DIR="/etc/systemd/system/joe-mcp-host-bridge.service.d"
WORKSPACE_DROPIN="$WORKSPACE_DROPIN_DIR/20-workspace-paths.conf"
RUNNER="/usr/local/libexec/joe-mcp-session-runner"
CLI="/usr/local/bin/joe"

for file in "$BRIDGE_TEMPLATE" "$SESSION_TEMPLATE" "$RUNNER_TEMPLATE" "$CLI_TEMPLATE" "$WORKSPACE_TEMPLATE"; do
  [[ -f "$file" ]] || { echo "Missing deployment template: $file" >&2; exit 1; }
done
if [[ "${JOE_MANAGED_NODE:-0}" != "1" ]]; then
  for file in "$DEPLOY_RUNNER_TEMPLATE" "$DEPLOY_SERVICE_TEMPLATE"; do
    [[ -f "$file" ]] || { echo "Missing controller deployment asset: $file" >&2; exit 1; }
  done
fi
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required" >&2; exit 1; }
command -v tmux >/dev/null || { echo "tmux is required for persistent sessions" >&2; exit 1; }

install -d -m 0755 /var/lib/joe-mcp-work
install -d -m 0700 /var/lib/joe-mcp-work/persistent-sessions
install -d -m 0700 /var/lib/joe-mcp-work/controller-state
install -d -m 0755 /usr/local/libexec
install -d -m 0755 /usr/local/bin
install -d -m 0755 "$WORKSPACE_DROPIN_DIR"
install -m 0755 "$ROOT/deploy/joe-mcp-git-askpass" /usr/local/libexec/joe-mcp-git-askpass
RUNTIME_ROOT="$ROOT"
if [[ "${JOE_MANAGED_NODE:-0}" != "1" ]]; then
  command -v git >/dev/null || { echo "git is required for controller host runtime activation" >&2; exit 1; }
  runtime_commit="$(git -C "$ROOT" rev-parse HEAD)"
  [[ "$runtime_commit" =~ ^[0-9a-f]{40}$ ]] || { echo "Unable to resolve exact Joe runtime commit" >&2; exit 1; }
  runtime_base="/var/lib/joe-mcp-work/controller-state/host-runtime"
  runtime_release="$runtime_base/$runtime_commit"
  install -d -m 0700 "$runtime_base"
  python3 - "$ROOT" "$runtime_release" "$runtime_commit" <<'PYRUNTIME'
import json
import os
import shutil
import sys
from pathlib import Path

project = Path(sys.argv[1]).resolve()
release = Path(sys.argv[2])
commit = sys.argv[3]
if release.exists():
    if release.is_symlink() or not release.is_dir():
        raise SystemExit("Existing Joe host runtime has unexpected type")
    raise SystemExit(0)
stage = release.parent / f".stage-{commit}-{os.getpid()}"
shutil.rmtree(stage, ignore_errors=True)
stage.mkdir(mode=0o700)
try:
    shutil.copytree(project / "src", stage / "src", ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"))
    scripts = stage / "scripts"
    scripts.mkdir(mode=0o755)
    for name in ("persistent_session_host.py", "persistent_session_runner.py"):
        shutil.copy2(project / "scripts" / name, scripts / name)
    (stage / "runtime.json").write_text(json.dumps({"version": 1, "commit": commit}, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(stage, release)
except Exception:
    shutil.rmtree(stage, ignore_errors=True)
    raise
PYRUNTIME
  ln -sfn "$runtime_commit" "$runtime_base/.current-new"
  mv -Tf "$runtime_base/.current-new" "$runtime_base/current"
  RUNTIME_ROOT="$runtime_base/current"
fi

escaped_root="${ROOT//\/\\}"
escaped_root="${escaped_root//&/\&}"
escaped_root="${escaped_root//|/\|}"
escaped_runtime="${RUNTIME_ROOT//\/\\}"
escaped_runtime="${escaped_runtime//&/\&}"
escaped_runtime="${escaped_runtime//|/\|}"
if [[ "${JOE_MANAGED_NODE:-0}" == "1" && ! -w "$(dirname "$CLI")" ]]; then
  # Older managed-node updater sandboxes did not grant /usr/local/bin write access.
  # Preserve the existing CLI for this bootstrap update; the newly installed updater
  # unit includes /usr/local/bin so the next update can refresh it normally.
  if [[ "${JOE_INSTALL_VERBOSE:-0}" == "1" ]]; then
    echo "Preserving existing Joe CLI until the updater sandbox is refreshed."
  fi
else
  sed "s|@PROJECT_ROOT@|$escaped_root|g" "$CLI_TEMPLATE" > "$CLI"
  chmod 0755 "$CLI"
fi
if [[ "${JOE_MANAGED_NODE:-0}" != "1" ]]; then
  sed -e "s|@RUNTIME_ROOT@|$escaped_runtime|g" "$DEPLOY_RUNNER_TEMPLATE" > "$DEPLOY_RUNNER"
  chmod 0755 "$DEPLOY_RUNNER"
fi

if [[ ! -f /var/lib/joe-mcp-work/actions.json ]]; then
  sed "s|/opt/joe-mcp/python/current|$escaped_root|g" "$ROOT/config/actions.json" > /var/lib/joe-mcp-work/actions.json
  chmod 0600 /var/lib/joe-mcp-work/actions.json
fi

if [[ ! -f "$WORKSPACE_FILE" ]]; then
  sed "s|/opt/joe-mcp/python/current|$escaped_root|g" "$WORKSPACE_TEMPLATE" > "$WORKSPACE_FILE"
  chmod 0600 "$WORKSPACE_FILE"
fi

python3 - "$WORKSPACE_FILE" "$ROOT" "$WORKSPACE_DROPIN" <<'PY'
import json
import sys
from pathlib import Path

policy_path = Path(sys.argv[1])
project_root = str(Path(sys.argv[2]).resolve())
dropin = Path(sys.argv[3])
try:
    data = json.loads(policy_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"Invalid Joe workspace policy: {exc}")
if not isinstance(data, dict) or data.get("version") not in {1, 2} or not isinstance(data.get("workspaces"), dict):
    raise SystemExit("Invalid Joe workspace policy structure")

write_paths: list[str] = []
read_only_paths: list[str] = []
workspace_roots: list[Path] = []
for name, raw in data["workspaces"].items():
    if not isinstance(raw, dict):
        raise SystemExit(f"Invalid workspace profile: {name}")
    root_raw = str(raw.get("root", ""))
    if not root_raw.startswith("/") or root_raw == "/" or any(ch in root_raw for ch in "\x00\r\n"):
        raise SystemExit(f"Unsafe workspace root in policy: {name}")
    root_path = Path(root_raw).resolve(strict=False)
    if root_path.is_dir():
        workspace_roots.append(root_path)

for name, raw in data["workspaces"].items():
    permissions = raw.get("permissions", {})
    if not isinstance(permissions, dict) or not permissions.get("modify", False):
        continue
    root = Path(str(raw.get("root", ""))).resolve(strict=False)
    if str(root) == project_root or not root.is_dir():
        continue
    write_paths.append(str(root))
    read_only_paths.extend((f"-{root}/.secrets", f"-{root}/.env"))
    marker = root / ".git"
    if marker.is_dir() and not marker.is_symlink():
        for suffix in ("config", "config.worktree", "hooks"):
            read_only_paths.append(f"-{marker}/{suffix}")
    elif marker.is_file() and not marker.is_symlink():
        try:
            line = marker.read_text(encoding="utf-8").strip()
        except OSError:
            line = ""
        if line.startswith("gitdir: "):
            git_dir = Path(line[8:].strip())
            if not git_dir.is_absolute():
                git_dir = (root / git_dir).resolve(strict=False)
            else:
                git_dir = git_dir.resolve(strict=False)
            for base_root in workspace_roots:
                common = base_root / ".git"
                worktrees = common / "worktrees"
                if common.is_dir() and git_dir.is_relative_to(worktrees):
                    for suffix in ("config", "config.worktree", "hooks"):
                        read_only_paths.append(f"-{common}/{suffix}")
                    read_only_paths.append(f"-{git_dir}/config.worktree")
                    break

write_paths = list(dict.fromkeys(write_paths))
read_only_paths = list(dict.fromkeys(read_only_paths))
if not write_paths:
    dropin.unlink(missing_ok=True)
    raise SystemExit(0)

def quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)

lines = ["[Service]", "ReadWritePaths=" + " ".join(quote(path) for path in write_paths)]
if read_only_paths:
    lines.append("ReadOnlyPaths=" + " ".join(quote(path) for path in read_only_paths))
dropin.write_text("\n".join(lines) + "\n", encoding="utf-8")
dropin.chmod(0o644)
PY

sed -e "s|@PROJECT_ROOT@|$escaped_root|g" -e "s|@RUNTIME_ROOT@|$escaped_runtime|g" "$RUNNER_TEMPLATE" > "$RUNNER"
chmod 0755 "$RUNNER"
sed -e "s|@PROJECT_ROOT@|$escaped_root|g" -e "s|@RUNTIME_ROOT@|$escaped_runtime|g" "$BRIDGE_TEMPLATE" > "$BRIDGE_UNIT"
sed -e "s|@PROJECT_ROOT@|$escaped_root|g" -e "s|@RUNTIME_ROOT@|$escaped_runtime|g" "$SESSION_TEMPLATE" > "$SESSION_UNIT"
chmod 0644 "$BRIDGE_UNIT" "$SESSION_UNIT"
if [[ "${JOE_MANAGED_NODE:-0}" != "1" ]]; then
  sed "s|@PROJECT_ROOT@|$escaped_root|g" "$DEPLOY_SERVICE_TEMPLATE" > "$DEPLOY_SERVICE_UNIT"
  chmod 0644 "$DEPLOY_SERVICE_UNIT"
fi

if [[ "${JOE_MANAGED_NODE:-0}" == "1" ]]; then
  python3 - "$BRIDGE_UNIT" "$ROOT" <<'PYMANAGED'
import sys
from pathlib import Path
unit = Path(sys.argv[1])
root = str(Path(sys.argv[2]).resolve())
text = unit.read_text(encoding='utf-8')
text = text.replace('Environment=JOE_NODE_ROLE=controller', 'Environment=JOE_NODE_ROLE=managed')
text = text.replace(
    f'Environment=JOE_WRITE_ROOTS={root},/var/lib/joe-mcp-work',
    'Environment=JOE_WRITE_ROOTS=/var/lib/joe-mcp-work',
)
text = text.replace(
    f'ReadWritePaths={root} /var/lib/joe-mcp-work',
    'ReadWritePaths=/var/lib/joe-mcp-work',
)
unit.write_text(text, encoding='utf-8')
PYMANAGED
fi

systemctl daemon-reload
if [[ "${JOE_INSTALL_VERBOSE:-0}" == "1" ]]; then
  systemctl enable joe-mcp-session-host.service joe-mcp-host-bridge.service
  if systemctl is-active --quiet joe-mcp-session-host.service; then
    echo "Joe MCP persistent session host already active; preserving existing sessions."
  else
    systemctl start joe-mcp-session-host.service
  fi
  systemctl restart joe-mcp-host-bridge.service
  echo "Joe MCP host bridge installed and restarted."
  echo "Persistent session host status: $(systemctl is-active joe-mcp-session-host.service)"
  systemctl --no-pager --full status joe-mcp-host-bridge.service | sed -n '1,12p'
else
  systemctl enable joe-mcp-session-host.service joe-mcp-host-bridge.service >/dev/null 2>&1
  if ! systemctl is-active --quiet joe-mcp-session-host.service; then
    systemctl start joe-mcp-session-host.service >/dev/null 2>&1
  fi
  systemctl restart joe-mcp-host-bridge.service >/dev/null 2>&1
fi
