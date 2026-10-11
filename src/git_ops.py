from __future__ import annotations

import os
import posixpath
import re
import stat
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from src.action_policy import authorize_git_action
from src.security import is_host_path_allowed, safe_host_path

GIT_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "HOME": "/",
    "PAGER": "cat",
    "GIT_PAGER": "cat",
    "NO_COLOR": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
}
MAX_GIT_OUTPUT_BYTES = 250_000
MAX_DIFF_PATHS = 200
MAX_STAGE_PATHS = 100
MAX_COMMIT_MESSAGE_CHARS = 300
REMOTE_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
GIT_ASKPASS_PATH = Path(os.getenv("JOE_GIT_ASKPASS", "/usr/local/libexec/joe-mcp-git-askpass"))
GIT_TOKEN_FILE = Path(os.getenv("JOE_GIT_TOKEN_FILE", "/var/lib/joe-mcp-work/.secrets/github.token"))
GITHUB_CLI_PATH = Path("/usr/bin/gh")
GITHUB_CLI_HELPER = "!/usr/bin/gh auth git-credential"
PROTECTED_REPO_PREFIXES = (".git", ".secrets", "data/auth", "data/audit")


class GitError(RuntimeError):
    pass


def _run(
    repo: Path,
    args: list[str],
    timeout: float = 8.0,
    max_bytes: int = MAX_GIT_OUTPUT_BYTES,
    extra_env: dict[str, str] | None = None,
) -> str:
    env = dict(GIT_ENV)
    if extra_env:
        env.update(extra_env)
    try:
        completed = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "credential.helper=",
                *args,
            ],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitError("git executable is unavailable on the host") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError("git operation timed out") from exc
    if completed.returncode != 0:
        message = completed.stderr[:4000].decode("utf-8", errors="replace").strip()
        raise GitError(message or f"git exited with status {completed.returncode}")
    raw = completed.stdout
    truncated = len(raw) > max_bytes
    text = raw[:max_bytes].decode("utf-8", errors="replace")
    if truncated:
        text += "\n[TRUNCATED]"
    return text


def resolve_repo(path: str) -> Path:
    candidate = safe_host_path(path, Path("/"))
    if not candidate.exists() or not candidate.is_dir():
        raise FileNotFoundError(path)
    top = _run(candidate, ["rev-parse", "--show-toplevel"], max_bytes=16_000).strip()
    if not top.startswith("/"):
        raise GitError("git returned an invalid repository root")
    root = safe_host_path(top, Path("/"))
    if not root.exists() or not root.is_dir():
        raise GitError("repository root no longer exists")
    return root


def _safe_repo_relpath(repo: Path, value: str) -> str | None:
    rel = str(value or "").strip()
    if not rel or rel.startswith("/") or "\x00" in rel:
        return None
    normalized = posixpath.normpath(rel)
    lowered = normalized.lower().rstrip("/")
    if any(lowered == prefix or lowered.startswith(prefix + "/") for prefix in PROTECTED_REPO_PREFIXES):
        return None
    root = repo.resolve(strict=False)
    resolved = (repo / normalized).resolve(strict=False)
    if resolved != root and not resolved.is_relative_to(root):
        return None
    if not is_host_path_allowed(str(resolved), Path("/")):
        return None
    return normalized


def _safe_repo_paths(repo: Path, paths: list[str]) -> tuple[list[str], int]:
    safe: list[str] = []
    restricted = 0
    for raw in paths:
        normalized = _safe_repo_relpath(repo, raw)
        if normalized is None:
            restricted += 1
        elif normalized not in safe:
            safe.append(normalized)
    return safe, restricted


def _stage_path(repo: Path, value: str) -> str:
    normalized = _safe_repo_relpath(repo, value)
    if normalized is None:
        raise GitError(f"Git stage path is restricted or invalid: {value}")
    candidate = repo / normalized
    if candidate.exists() and candidate.is_dir():
        raise GitError(f"Git stage path must name a file, not a directory: {normalized}")
    return normalized


def _name_only(repo: Path, staged: bool) -> list[str]:
    args = ["diff", "--name-only", "-z", "--no-ext-diff", "--no-textconv"]
    if staged:
        args.append("--cached")
    args.append("--")
    output = _run(repo, args, max_bytes=1_000_000)
    return [item for item in output.split("\x00") if item and item != "[TRUNCATED]"]


def _untracked(repo: Path) -> list[str]:
    output = _run(repo, ["ls-files", "--others", "--exclude-standard", "-z"], max_bytes=1_000_000)
    return [item for item in output.split("\x00") if item and item != "[TRUNCATED]"]


def git_status(path: str) -> dict[str, Any]:
    repo = resolve_repo(path)
    branch = _run(repo, ["branch", "--show-current"], max_bytes=4096).strip()
    if not branch:
        branch = f"detached@{_run(repo, ['rev-parse', '--short', 'HEAD'], max_bytes=4096).strip()}"

    staged, staged_hidden = _safe_repo_paths(repo, _name_only(repo, True))
    unstaged, unstaged_hidden = _safe_repo_paths(repo, _name_only(repo, False))
    untracked, untracked_hidden = _safe_repo_paths(repo, _untracked(repo))

    upstream = None
    ahead = behind = None
    try:
        upstream = _run(repo, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"], max_bytes=4096).strip()
        counts = _run(repo, ["rev-list", "--left-right", "--count", "HEAD...@{u}"], max_bytes=4096).strip().split()
        if len(counts) == 2:
            ahead, behind = int(counts[0]), int(counts[1])
    except (GitError, ValueError):
        upstream = None

    return {
        "repository": str(repo),
        "branch": branch,
        "upstream": upstream,
        "ahead": ahead,
        "behind": behind,
        "staged": staged[:MAX_DIFF_PATHS],
        "unstaged": unstaged[:MAX_DIFF_PATHS],
        "untracked": untracked[:MAX_DIFF_PATHS],
        "restricted_paths_hidden": staged_hidden + unstaged_hidden + untracked_hidden,
        "clean": not staged and not unstaged and not untracked,
        "paths_truncated": any(len(items) > MAX_DIFF_PATHS for items in (staged, unstaged, untracked)),
    }


def git_diff(path: str, staged: bool = False, max_bytes: int = 200_000) -> dict[str, Any]:
    repo = resolve_repo(path)
    changed = _name_only(repo, bool(staged))
    safe_paths, restricted = _safe_repo_paths(repo, changed)
    selected = safe_paths[:MAX_DIFF_PATHS]
    if not selected:
        diff = ""
    else:
        args = ["diff", "--no-ext-diff", "--no-textconv", "--no-color"]
        if staged:
            args.append("--cached")
        args.extend(["--", *selected])
        limit = max(1, min(int(max_bytes), MAX_GIT_OUTPUT_BYTES))
        diff = _run(repo, args, max_bytes=limit)
    return {
        "repository": str(repo),
        "staged": bool(staged),
        "paths": selected,
        "restricted_paths_hidden": restricted,
        "paths_truncated": len(safe_paths) > MAX_DIFF_PATHS,
        "diff": diff,
    }


def git_log(path: str, max_count: int = 20) -> dict[str, Any]:
    repo = resolve_repo(path)
    count = max(1, min(int(max_count), 100))
    output = _run(
        repo,
        [
            "log",
            f"--max-count={count}",
            "--date=iso-strict",
            "--pretty=format:%H%x09%h%x09%ad%x09%an%x09%s",
        ],
        max_bytes=MAX_GIT_OUTPUT_BYTES,
    )
    commits: list[dict[str, str]] = []
    for line in output.splitlines():
        parts = line.split("\t", 4)
        if len(parts) != 5:
            continue
        full, short, date, author, subject = parts
        commits.append({
            "commit": full,
            "short": short,
            "date": date,
            "author": author[:200],
            "subject": subject[:500],
        })
    return {"repository": str(repo), "commits": commits, "count": len(commits)}


def git_credentials_info() -> dict[str, Any]:
    token_secure = False
    askpass_secure = False
    try:
        token_stat = GIT_TOKEN_FILE.lstat()
        token_mode = stat.S_IMODE(token_stat.st_mode)
        token_secure = (
            stat.S_ISREG(token_stat.st_mode)
            and token_stat.st_uid == 0
            and token_mode & 0o077 == 0
            and token_stat.st_size > 0
        )
    except OSError:
        token_secure = False
    try:
        askpass_stat = GIT_ASKPASS_PATH.lstat()
        askpass_mode = stat.S_IMODE(askpass_stat.st_mode)
        askpass_secure = (
            stat.S_ISREG(askpass_stat.st_mode)
            and askpass_stat.st_uid == 0
            and askpass_mode & 0o022 == 0
            and os.access(GIT_ASKPASS_PATH, os.X_OK)
        )
    except OSError:
        askpass_secure = False
    github_cli_secure = False
    try:
        github_cli_stat = GITHUB_CLI_PATH.lstat()
        github_cli_mode = stat.S_IMODE(github_cli_stat.st_mode)
        github_cli_secure = (
            stat.S_ISREG(github_cli_stat.st_mode)
            and github_cli_stat.st_uid == 0
            and github_cli_mode & 0o022 == 0
            and os.access(GITHUB_CLI_PATH, os.X_OK)
        )
    except OSError:
        github_cli_secure = False
    joe_token_ready = token_secure and askpass_secure
    provider = "joe_token" if joe_token_ready else "github_cli" if github_cli_secure else ""
    return {
        "configured": bool(provider),
        "provider": provider,
        "token_secure": token_secure,
        "askpass_secure": askpass_secure,
        "github_cli_secure": github_cli_secure,
    }


def _change_sets(repo: Path) -> tuple[list[str], list[str], list[str], int]:
    staged_raw = _name_only(repo, True)
    unstaged_raw = _name_only(repo, False)
    untracked_raw = _untracked(repo)
    staged, staged_hidden = _safe_repo_paths(repo, staged_raw)
    unstaged, unstaged_hidden = _safe_repo_paths(repo, unstaged_raw)
    untracked, untracked_hidden = _safe_repo_paths(repo, untracked_raw)
    restricted = staged_hidden + unstaged_hidden + untracked_hidden
    return staged, unstaged, untracked, restricted


def _ensure_no_clean_filters(repo: Path, paths: list[str]) -> None:
    if not paths:
        return
    output = _run(repo, ["check-attr", "-z", "filter", "--", *paths], max_bytes=250_000)
    fields = output.split("\x00")
    for index in range(0, len(fields) - 2, 3):
        file_path, attribute, value = fields[index:index + 3]
        if attribute == "filter" and value not in {"", "unspecified", "unset"}:
            raise GitError(f"Git clean filter is configured for staged path: {file_path}")


def git_stage(path: str, paths: list[str]) -> dict[str, Any]:
    repo = resolve_repo(path)
    authorize_git_action(str(repo), "stage")
    if not isinstance(paths, list) or not paths:
        raise GitError("git_stage requires at least one explicit file path")
    if len(paths) > MAX_STAGE_PATHS:
        raise GitError(f"git_stage accepts at most {MAX_STAGE_PATHS} paths")

    selected: list[str] = []
    for raw in paths:
        normalized = _stage_path(repo, str(raw))
        if normalized not in selected:
            selected.append(normalized)

    staged_before, unstaged_before, untracked_before, restricted = _change_sets(repo)
    if restricted:
        raise GitError("Repository contains restricted changed paths; Git staging is blocked")
    changed = set(staged_before + unstaged_before + untracked_before)
    missing = [item for item in selected if item not in changed]
    if missing:
        raise GitError(f"Path is not an explicit changed file: {missing[0]}")

    _ensure_no_clean_filters(repo, selected)
    _run(repo, ["add", "--", *selected], timeout=15.0, max_bytes=16_000)
    staged_after, _, _, restricted_after = _change_sets(repo)
    if restricted_after:
        raise GitError("Restricted path appeared in the staged set")
    return {
        "repository": str(repo),
        "staged_paths": selected,
        "staged": staged_after[:MAX_DIFF_PATHS],
        "staged_count": len(staged_after),
    }


def _commit_message(value: str) -> str:
    message = str(value or "").strip()
    if not message:
        raise GitError("Commit message cannot be empty")
    if len(message) > MAX_COMMIT_MESSAGE_CHARS:
        raise GitError(f"Commit message exceeds {MAX_COMMIT_MESSAGE_CHARS} characters")
    if "\x00" in message or "\n" in message or "\r" in message:
        raise GitError("Commit message must be a single line")
    return message


def git_commit(path: str, message: str) -> dict[str, Any]:
    repo = resolve_repo(path)
    authorize_git_action(str(repo), "commit")
    subject = _commit_message(message)
    staged, staged_hidden = _safe_repo_paths(repo, _name_only(repo, True))
    if staged_hidden:
        raise GitError("Restricted path is present in the Git index; commit is blocked")
    if not staged:
        raise GitError("No staged changes are available to commit")

    _run(
        repo,
        [
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--no-gpg-sign",
            "-m",
            subject,
        ],
        timeout=30.0,
        max_bytes=32_000,
    )
    commit = _run(repo, ["rev-parse", "HEAD"], max_bytes=4096).strip()
    short = _run(repo, ["rev-parse", "--short", "HEAD"], max_bytes=4096).strip()
    branch = _run(repo, ["branch", "--show-current"], max_bytes=4096).strip()
    return {
        "repository": str(repo),
        "commit": commit,
        "short": short,
        "branch": branch,
        "subject": subject,
        "paths": staged[:MAX_DIFF_PATHS],
    }


def _push_target(repo: Path, remote: str, expected_branch: str) -> tuple[str, str, int, int]:
    remote_name = str(remote or "").strip()
    if not REMOTE_RE.fullmatch(remote_name):
        raise GitError("Invalid Git remote name")
    branch = _run(repo, ["branch", "--show-current"], max_bytes=4096).strip()
    if not branch:
        raise GitError("Git push is not allowed from a detached HEAD")
    expected = str(expected_branch or "").strip()
    if not expected or expected != branch:
        raise GitError(f"Expected branch does not match current branch: {branch}")
    _run(repo, ["check-ref-format", "--branch", branch], max_bytes=4096)

    upstream = _run(
        repo,
        ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
        max_bytes=4096,
    ).strip()
    if "/" not in upstream:
        raise GitError("Current branch has no usable upstream")
    upstream_remote, upstream_branch = upstream.split("/", 1)
    if upstream_remote != remote_name or upstream_branch != branch:
        raise GitError("Push target must exactly match the current branch upstream")

    remote_url = _run(repo, ["remote", "get-url", "--push", remote_name], max_bytes=16_000).strip()
    parsed = urlsplit(remote_url)
    if parsed.scheme.lower() != "https" or (parsed.hostname or "").lower() != "github.com":
        raise GitError("Joe Git push currently supports only HTTPS GitHub remotes")
    if parsed.username or parsed.password:
        raise GitError("Git remote URL must not contain embedded credentials")

    counts = _run(repo, ["rev-list", "--left-right", "--count", "HEAD...@{u}"], max_bytes=4096).strip().split()
    if len(counts) != 2:
        raise GitError("Unable to determine Git ahead/behind state")
    ahead, behind = int(counts[0]), int(counts[1])
    if behind:
        raise GitError("Local branch is behind its upstream; push is blocked")
    return branch, upstream, ahead, behind


def git_push(path: str, expected_branch: str, remote: str = "origin") -> dict[str, Any]:
    repo = resolve_repo(path)
    authorize_git_action(str(repo), "push")
    staged, unstaged, untracked, restricted = _change_sets(repo)
    if restricted:
        raise GitError("Repository contains restricted changed paths; push is blocked")
    if staged or unstaged or untracked:
        raise GitError("Git push requires a clean worktree and index")

    branch, upstream, ahead, _behind = _push_target(repo, remote, expected_branch)
    commit = _run(repo, ["rev-parse", "HEAD"], max_bytes=4096).strip()
    if ahead == 0:
        return {
            "repository": str(repo),
            "remote": remote,
            "branch": branch,
            "upstream": upstream,
            "commit": commit,
            "pushed": False,
            "already_up_to_date": True,
        }

    credentials = git_credentials_info()
    provider = str(credentials.get("provider") or "")
    if not credentials.get("configured") or provider not in {"joe_token", "github_cli"}:
        raise GitError("No secure GitHub credential provider is available")

    push_args = ["-c", "core.hooksPath=/dev/null"]
    push_env: dict[str, str] = {}
    if provider == "github_cli":
        push_args.extend(["-c", f"credential.helper={GITHUB_CLI_HELPER}"])
        push_env.update({"HOME": "/root", "GH_CONFIG_DIR": "/root/.config/gh"})
    else:
        push_env.update({
            "GIT_ASKPASS": str(GIT_ASKPASS_PATH),
            "JOE_GIT_TOKEN_FILE": str(GIT_TOKEN_FILE),
        })
    push_args.extend([
        "push",
        "--porcelain",
        remote,
        f"refs/heads/{branch}:refs/heads/{branch}",
    ])

    _run(
        repo,
        push_args,
        timeout=60.0,
        max_bytes=32_000,
        extra_env=push_env,
    )
    return {
        "repository": str(repo),
        "remote": remote,
        "branch": branch,
        "upstream": upstream,
        "commit": commit,
        "pushed": True,
        "commits_pushed": ahead,
    }


BRANCH_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


def _clean_for_branch_change(repo: Path) -> None:
    staged, unstaged, untracked, restricted = _change_sets(repo)
    if restricted:
        raise GitError("Repository contains restricted changed paths; branch operation is blocked")
    if staged or unstaged or untracked:
        raise GitError("Git branch changes require a clean worktree and index")


def _branch_name(repo: Path, value: str) -> str:
    name = str(value or "").strip()
    if not BRANCH_NAME_RE.fullmatch(name) or ".." in name or "@{" in name or name.endswith(("/", ".", ".lock")):
        raise GitError("Invalid Git branch name")
    _run(repo, ["check-ref-format", "--branch", name], max_bytes=4096)
    return name


def git_branches(path: str, max_count: int = 200) -> dict[str, Any]:
    repo = resolve_repo(path)
    limit = max(1, min(int(max_count), 500))
    current = _run(repo, ["branch", "--show-current"], max_bytes=4096).strip()
    output = _run(
        repo,
        ["for-each-ref", "--sort=-committerdate", "--format=%(refname:short)%09%(objectname)%09%(upstream:short)%09%(committerdate:iso-strict)%09%(subject)", "refs/heads/"],
        max_bytes=MAX_GIT_OUTPUT_BYTES,
    )
    branches: list[dict[str, Any]] = []
    for line in output.splitlines():
        parts = line.split("\t", 4)
        if len(parts) != 5:
            continue
        name, commit, upstream, date, subject = parts
        branches.append({
            "name": name,
            "current": name == current,
            "commit": commit,
            "upstream": upstream or None,
            "date": date or None,
            "subject": subject[:500],
        })
        if len(branches) >= limit:
            break
    return {"repository": str(repo), "current": current or None, "branches": branches, "count": len(branches)}


def git_branch_create(path: str, name: str, start_commit: str = "") -> dict[str, Any]:
    repo = resolve_repo(path)
    authorize_git_action(str(repo), "branch_create")
    _clean_for_branch_change(repo)
    branch = _branch_name(repo, name)
    start = str(start_commit or "").strip()
    if start:
        if not COMMIT_RE.fullmatch(start):
            raise GitError("Branch start_commit must be a Git commit hash")
        start = _run(repo, ["rev-parse", "--verify", f"{start}^{{commit}}"], max_bytes=4096).strip()
    else:
        start = _run(repo, ["rev-parse", "HEAD"], max_bytes=4096).strip()
    try:
        _run(repo, ["show-ref", "--verify", f"refs/heads/{branch}"], max_bytes=4096)
    except GitError:
        pass
    else:
        raise GitError(f"Git branch already exists: {branch}")
    _run(repo, ["branch", "--no-track", branch, start], timeout=10.0, max_bytes=16_000)
    return {"repository": str(repo), "branch": branch, "start_commit": start, "created": True}


def git_branch_switch(path: str, name: str) -> dict[str, Any]:
    repo = resolve_repo(path)
    authorize_git_action(str(repo), "branch_switch")
    _clean_for_branch_change(repo)
    branch = _branch_name(repo, name)
    _run(repo, ["show-ref", "--verify", f"refs/heads/{branch}"], max_bytes=4096)
    before = _run(repo, ["branch", "--show-current"], max_bytes=4096).strip()
    _run(repo, ["switch", "--no-guess", branch], timeout=15.0, max_bytes=16_000)
    after = _run(repo, ["branch", "--show-current"], max_bytes=4096).strip()
    return {"repository": str(repo), "before": before or None, "branch": after or branch, "switched": before != after}


def git_reset_to_commit(path: str, target_commit: str, expected_head: str, confirm: bool = False) -> dict[str, Any]:
    repo = resolve_repo(path)
    authorize_git_action(str(repo), "reset")
    if not bool(confirm):
        raise GitError("Git reset requires confirm=true")
    _clean_for_branch_change(repo)
    target_raw = str(target_commit or "").strip()
    expected_raw = str(expected_head or "").strip()
    if not COMMIT_RE.fullmatch(target_raw) or not COMMIT_RE.fullmatch(expected_raw):
        raise GitError("Git reset requires explicit commit hashes")
    current = _run(repo, ["rev-parse", "HEAD"], max_bytes=4096).strip()
    expected = _run(repo, ["rev-parse", "--verify", f"{expected_raw}^{{commit}}"], max_bytes=4096).strip()
    if current != expected:
        raise GitError("Git HEAD changed since approval; reset is blocked")
    target = _run(repo, ["rev-parse", "--verify", f"{target_raw}^{{commit}}"], max_bytes=4096).strip()
    if target == current:
        return {"repository": str(repo), "before": current, "after": current, "reset": False}
    try:
        _run(repo, ["merge-base", "--is-ancestor", target, current], max_bytes=4096)
    except GitError as exc:
        raise GitError("Reset target must be an ancestor of current HEAD") from exc
    _run(repo, ["reset", "--hard", target], timeout=20.0, max_bytes=32_000)
    after = _run(repo, ["rev-parse", "HEAD"], max_bytes=4096).strip()
    return {"repository": str(repo), "before": current, "after": after, "reset": True, "mode": "hard"}


def git_rollback_last(path: str, expected_head: str, confirm: bool = False) -> dict[str, Any]:
    repo = resolve_repo(path)
    current = _run(repo, ["rev-parse", "HEAD"], max_bytes=4096).strip()
    expected_raw = str(expected_head or "").strip()
    if not COMMIT_RE.fullmatch(expected_raw):
        raise GitError("Rollback requires the explicitly approved current commit hash")
    expected = _run(repo, ["rev-parse", "--verify", f"{expected_raw}^{{commit}}"], max_bytes=4096).strip()
    if current != expected:
        raise GitError("Git HEAD changed since approval; rollback is blocked")
    parent = _run(repo, ["rev-parse", "HEAD^"], max_bytes=4096).strip()
    return git_reset_to_commit(str(repo), parent, current, confirm)
