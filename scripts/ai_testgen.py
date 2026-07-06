#!/usr/bin/env python3
"""
ai_testgen — Portable, language-agnostic AI test generation & review
====================================================================
Drop this single file into any repository. It:

  1. Computes a git diff of your source files (glob from config)
  2. Asks an AI model to write tests for the changed code
  3. Writes them to your generated-tests dir and runs your test command
  4. On failure, asks the AI to classify: broken TEST vs real SOURCE bug
     - broken test (incl. syntax/collection errors) -> regenerate & retry
     - real source bug -> write bug_report.md and exit 1

Nothing here is tied to a specific project or language. Everything that
differs per repo (language, framework, source glob, test dir, run command,
project description) comes from config, resolved in this order:

    env vars  >  .aitestgen.toml / .aitestgen.json  >  language preset  >  auto-detect

Supported AI providers (auto-detected from whichever key is set, or AI_PROVIDER):
    anthropic  -> ANTHROPIC_API_KEY   (default model: claude-sonnet-4-6)
    deepseek   -> DEEPSEEK_API_KEY     (default model: deepseek-chat)
    openai     -> OPENAI_API_KEY       (default model: gpt-4o)

Usage:
    python ai_testgen.py [--base-ref HEAD~1] [--head-ref HEAD] [--config PATH]
    python ai_testgen.py --print-config      # show resolved config and exit
    python ai_testgen.py --print-install     # print the configured install cmd
    AI_PROVIDER=anthropic ANTHROPIC_API_KEY=sk-... python ai_testgen.py
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

# ── Repo root (independent of where the script is dropped) ────────────────────

def _find_repo_root(start: Path) -> Path:
    cur = start.resolve()
    for parent in (cur, *cur.parents):
        if (parent / ".git").exists():
            return parent
    return start.parent  # fallback: script's parent dir


PROJECT_ROOT = _find_repo_root(Path(__file__).parent)

MAX_RETRIES    = int(os.environ.get("AITG_MAX_RETRIES", "2"))
MAX_DIFF_CHARS = int(os.environ.get("AITG_MAX_DIFF_CHARS", "12000"))
MAX_SRC_CHARS  = int(os.environ.get("AITG_MAX_SRC_CHARS", "8000"))


# ── Language presets (conveniences; everything is overridable via config) ─────

PRESETS: dict[str, dict] = {
    "python": {
        "language":     "Python",
        "framework":    "pytest",
        "source_glob":  "**/*.py",
        "test_dir":     "tests/generated",
        "test_ext":     ".py",
        "code_fence":   "python",
        "mock_libs":    "unittest.mock (mock out sockets, network I/O, filesystem, subprocess)",
        "run_cmd":      ["{py}", "-m", "pytest", "{test_path}", "-q", "--tb=short", "--no-header"],
        "install":      "pip install -r requirements.txt pytest || pip install pytest",
        "detect_files": ["pyproject.toml", "setup.py", "requirements.txt"],
    },
    "javascript": {
        "language":     "JavaScript/TypeScript",
        "framework":    "Jest",
        "source_glob":  "src/**/*.{js,ts,jsx,tsx}",
        "test_dir":     "__tests__/generated",
        "test_ext":     ".test.js",
        "code_fence":   "javascript",
        "mock_libs":    "jest.mock (mock out network, timers, fs)",
        "run_cmd":      ["npx", "jest", "{test_path}", "--silent"],
        "install":      "npm ci || npm install",
        "detect_files": ["package.json"],
    },
    "go": {
        "language":     "Go",
        "framework":    "the standard testing package",
        "source_glob":  "**/*.go",
        "test_dir":     "aigen",
        "test_ext":     "_ai_test.go",
        "code_fence":   "go",
        "mock_libs":    "interfaces / httptest (avoid real network)",
        "run_cmd":      ["go", "test", "./..."],
        "install":      "go mod download",
        "detect_files": ["go.mod"],
    },
}


# ── AI provider selection ─────────────────────────────────────────────────────

_PROVIDERS = {
    "anthropic": {"env_key": "ANTHROPIC_API_KEY", "default_model": "claude-sonnet-4-6"},
    "deepseek":  {"env_key": "DEEPSEEK_API_KEY",  "default_model": "deepseek-chat",
                  "base_url": "https://api.deepseek.com"},
    "openai":    {"env_key": "OPENAI_API_KEY",    "default_model": "gpt-4o"},
}


def detect_provider() -> str:
    explicit = os.environ.get("AI_PROVIDER", "").lower()
    if explicit in _PROVIDERS:
        return explicit
    for name, cfg in _PROVIDERS.items():
        if os.environ.get(cfg["env_key"]):
            return name
    return "anthropic"


# ── Config resolution ─────────────────────────────────────────────────────────

def _read_config_file(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    # TOML: stdlib tomllib (3.11+), else optional tomli, else give up cleanly.
    try:
        import tomllib  # type: ignore
        return tomllib.loads(text)
    except ModuleNotFoundError:
        try:
            import tomli  # type: ignore
            return tomli.loads(text)
        except ModuleNotFoundError:
            print("⚠️  Cannot parse TOML (need Python 3.11+ or `pip install tomli`); "
                  "use .aitestgen.json instead.")
            return {}


def _autodetect_language() -> str:
    for lang, preset in PRESETS.items():
        if any((PROJECT_ROOT / f).exists() for f in preset.get("detect_files", [])):
            return lang
    return "python"


# Env var overrides. AITG_RUN_CMD may be a JSON list or a shell-ish string.
_ENV_OVERRIDES = {
    "AITG_LANGUAGE":    "language",
    "AITG_FRAMEWORK":   "framework",
    "AITG_SOURCE_GLOB": "source_glob",
    "AITG_TEST_DIR":    "test_dir",
    "AITG_TEST_EXT":    "test_ext",
    "AITG_CODE_FENCE":  "code_fence",
    "AITG_MOCK_LIBS":   "mock_libs",
    "AITG_INSTALL":     "install",
    "AITG_PROJECT":     "project",
    "AITG_RUN_CMD":     "run_cmd",
}


def load_config(cli_config: str | None) -> dict:
    # 1. locate config file
    candidates = [Path(cli_config)] if cli_config else [
        PROJECT_ROOT / ".aitestgen.toml",
        PROJECT_ROOT / ".aitestgen.json",
    ]
    file_cfg: dict = {}
    for c in candidates:
        if c.exists():
            file_cfg = _read_config_file(c)
            break

    # 2. choose base preset
    lang_key = (
        os.environ.get("AITG_LANGUAGE")
        or file_cfg.get("language_preset")
        or file_cfg.get("preset")
        or (file_cfg.get("language", "").lower() if file_cfg.get("language") else "")
        or _autodetect_language()
    ).lower()
    # map friendly names to preset keys
    alias = {"js": "javascript", "ts": "javascript", "typescript": "javascript",
             "py": "python", "golang": "go"}
    lang_key = alias.get(lang_key, lang_key)
    cfg = dict(PRESETS.get(lang_key, PRESETS["python"]))

    # 3. overlay file config, then env overrides
    cfg.update({k: v for k, v in file_cfg.items() if v is not None})
    for env, key in _ENV_OVERRIDES.items():
        val = os.environ.get(env)
        if not val:
            continue
        if key == "run_cmd":
            try:
                cfg[key] = json.loads(val)
            except json.JSONDecodeError:
                cfg[key] = val.split()
        else:
            cfg[key] = val

    cfg.setdefault("project", PROJECT_ROOT.name)
    return cfg


# ── Git diff ──────────────────────────────────────────────────────────────────

def get_diff(base_ref: str, head_ref: str, source_glob: str) -> tuple[str, list[Path]]:
    """Diff + changed files matching the configured source glob."""
    pathspec = f":(glob){source_glob}"
    try:
        raw = subprocess.check_output(
            ["git", "diff", base_ref, head_ref, "--", pathspec],
            cwd=PROJECT_ROOT, stderr=subprocess.DEVNULL, text=True,
        )
        changed = subprocess.check_output(
            ["git", "diff", "--name-only", base_ref, head_ref, "--", pathspec],
            cwd=PROJECT_ROOT, stderr=subprocess.DEVNULL, text=True,
        ).strip().splitlines()
    except subprocess.CalledProcessError:
        return "", []

    files = [PROJECT_ROOT / f for f in changed if (PROJECT_ROOT / f).exists()]
    return raw[:MAX_DIFF_CHARS], files


def read_source(paths: list[Path]) -> str:
    parts = []
    for p in paths:
        try:
            parts.append(f"# === {p.name} ===\n{p.read_text(encoding='utf-8')[:MAX_SRC_CHARS]}")
        except OSError:
            pass
    return "\n\n".join(parts)


def read_existing_tests(test_dir: Path, test_ext: str) -> str:
    """Existing tests (excluding the generated dir) for context / de-duplication."""
    parent = test_dir.parent if test_dir.name == "generated" else test_dir
    parts = []
    if parent.exists():
        pattern = f"*{test_ext}" if test_ext.startswith(".") else f"*{test_ext}"
        for tf in sorted(parent.rglob(pattern)):
            if test_dir in tf.parents:
                continue
            try:
                parts.append(f"# === {tf.name} ===\n{tf.read_text(encoding='utf-8')[:4000]}")
            except OSError:
                pass
    return "\n\n".join(parts[:8])


# ── AI API ────────────────────────────────────────────────────────────────────

def call_ai(system: str, user: str, temperature: float = 0.2, max_tokens: int = 4096) -> str:
    provider = detect_provider()
    cfg      = _PROVIDERS[provider]
    api_key  = os.environ.get(cfg["env_key"])
    if not api_key:
        raise RuntimeError(f"Missing API key env var '{cfg['env_key']}'.")
    model = os.environ.get("AI_MODEL") or cfg["default_model"]

    if provider == "anthropic":
        try:
            import anthropic
        except ImportError:
            print("❌ pip install anthropic"); sys.exit(1)
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model=model, max_tokens=max_tokens, temperature=temperature,
            system=system, messages=[{"role": "user", "content": user}],
        )
        return msg.content[0].text

    # deepseek / openai — both OpenAI-compatible
    try:
        from openai import OpenAI
    except ImportError:
        print("❌ pip install openai"); sys.exit(1)
    kw = {"api_key": api_key}
    if "base_url" in cfg:
        kw["base_url"] = cfg["base_url"]
    client = OpenAI(**kw)
    resp = client.chat.completions.create(
        model=model, max_tokens=max_tokens, temperature=temperature,
        messages=[{"role": "system", "content": system},
                  {"role": "user", "content": user}],
    )
    return resp.choices[0].message.content


def extract_code_block(text: str, fence: str) -> str:
    """Extract the first ```<fence> ... ``` (or any ``` ... ```) block."""
    for opener in (f"```{fence}", "```"):
        if opener in text:
            start = text.index(opener) + len(opener)
            end   = text.find("```", start)
            return text[start:end if end != -1 else None].strip()
    return text.strip()


# ── Prompts (parameterised by language/framework/project) ─────────────────────

def _gen_system(cfg: dict) -> str:
    return textwrap.dedent(f"""
        You are an expert {cfg['language']} test engineer writing tests with
        {cfg['framework']} for a project called "{cfg['project']}".

        RULES:
        - Write only unit tests that need no network or external services;
          mock them out using {cfg['mock_libs']}.
        - Each test must run independently.
        - Test ONLY the changed/added functions shown in the diff.
        - Do NOT duplicate existing tests; complement them.
        - Cover success, failure, and edge-case paths.
        - Include all necessary imports at the top of the file.
        - Return ONLY valid {cfg['language']} code inside a ```{cfg['code_fence']}
          ... ``` block — no prose, no explanation.
    """).strip()


def generate_tests(cfg: dict, diff: str, source: str, existing: str) -> str:
    user = textwrap.dedent(f"""
        Review this git diff and write {cfg['framework']} tests for the
        changed/added functions.

        ## GIT DIFF
        ```diff
        {diff}
        ```

        ## CHANGED SOURCE FILES
        ```{cfg['code_fence']}
        {source}
        ```

        ## EXISTING TESTS (do not repeat these)
        ```{cfg['code_fence']}
        {existing[:6000]}
        ```

        Return the new tests in a single ```{cfg['code_fence']} ... ``` block.
    """).strip()
    return call_ai(_gen_system(cfg), user, max_tokens=8192)


_CLASSIFY_SYSTEM = textwrap.dedent("""
    You are a senior test engineer reviewing a FAILED test run. A generated
    test file failed. Decide the root cause:

      A) TEST_BUG   — the test itself is wrong: bad syntax, could not be
                      collected/compiled, wrong mock target, unrealistic
                      assertion, wrong import. The source code is fine.
      B) SOURCE_BUG — the test is reasonable and it exposed a real bug in the
                      source code.

    Respond with ONLY this JSON (nothing else):
    {
      "classification": "test_bug" | "source_bug",
      "confidence": 0.0-1.0,
      "reason": "one sentence",
      "bug_description": "if source_bug: what's broken and how to fix; else ''"
    }
""").strip()


def classify_failure(cfg: dict, source: str, test_code: str, output: str) -> dict:
    user = textwrap.dedent(f"""
        ## SOURCE CODE
        ```{cfg['code_fence']}
        {source[:6000]}
        ```

        ## GENERATED TEST FILE
        ```{cfg['code_fence']}
        {test_code[:6000]}
        ```

        ## TEST RUNNER OUTPUT
        ```
        {output[-4000:]}
        ```
    """).strip()
    raw = call_ai(_CLASSIFY_SYSTEM, user, temperature=0.0, max_tokens=1024)
    try:
        blob = raw[raw.index("{"):raw.rindex("}") + 1]
        return json.loads(blob)
    except (ValueError, json.JSONDecodeError):
        return {"classification": "test_bug", "confidence": 0.0,
                "reason": "could not parse classifier response", "bug_description": ""}


_FIX_SYSTEM = textwrap.dedent("""
    You are a senior test engineer. The generated test file below failed for a
    TEST-side reason (bad syntax, could not be collected/compiled, wrong mock,
    unrealistic assertion) — NOT a real source bug. Rewrite the WHOLE file so it
    is valid and runnable, preserving the original testing intent.

    RULES:
    - Return a complete, self-contained, collectible/compilable file — not a snippet.
    - Fix the reported error; keep all otherwise-correct tests.
    - All imports at the top, once.
    - Return ONLY valid code inside a code block — no prose.
""").strip()


def fix_test_file(cfg: dict, test_code: str, output: str, source: str) -> str:
    user = textwrap.dedent(f"""
        ## BROKEN TEST FILE (WHOLE)
        ```{cfg['code_fence']}
        {test_code}
        ```

        ## TEST RUNNER ERROR
        ```
        {output[-3000:]}
        ```

        ## SOURCE CODE (reference)
        ```{cfg['code_fence']}
        {source[:6000]}
        ```

        Return the fixed WHOLE file in a ```{cfg['code_fence']} ... ``` block.
    """).strip()
    return call_ai(_FIX_SYSTEM, user, max_tokens=8192)


# ── Test runner ───────────────────────────────────────────────────────────────

def run_tests(cfg: dict, test_file: Path) -> tuple[int, str]:
    cmd = [
        part.replace("{py}", sys.executable)
            .replace("{test_path}", str(test_file))
            .replace("{test_dir}", str(test_file.parent))
        for part in cfg["run_cmd"]
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=PROJECT_ROOT)
    except FileNotFoundError as e:
        return 127, f"Test runner not found: {e}"
    return result.returncode, result.stdout + result.stderr


# ── Bug report ────────────────────────────────────────────────────────────────

def write_bug_report(cfg: dict, analysis: dict, test_file: Path, output: str) -> Path:
    report = PROJECT_ROOT / "bug_report.md"
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    report.write_text("\n".join([
        f"## 🐛 {cfg['project']} — AI Test Review Bug Report",
        "",
        f"**Date:** {ts}  ",
        f"**Test file:** `{test_file.relative_to(PROJECT_ROOT)}`  ",
        f"**Confidence:** {analysis.get('confidence', 0):.0%}",
        "",
        "**Description:**  ",
        analysis.get("bug_description", "—"),
        "",
        "**Test runner output:**",
        "```",
        "\n".join(output.splitlines()[-30:]),
        "```",
    ]), encoding="utf-8")
    return report


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="Portable AI test generation & review")
    ap.add_argument("--base-ref", default="HEAD~1")
    ap.add_argument("--head-ref", default="HEAD")
    ap.add_argument("--config", default=None, help="Path to .aitestgen.toml/.json")
    ap.add_argument("--dry-run", action="store_true", help="Generate but do not run")
    ap.add_argument("--print-config", action="store_true")
    ap.add_argument("--print-install", action="store_true")
    args = ap.parse_args()

    cfg = load_config(args.config)

    if args.print_install:
        print(cfg.get("install", ""))
        return 0
    if args.print_config:
        print(json.dumps(cfg, indent=2, default=str))
        return 0

    provider = detect_provider()
    if not os.environ.get(_PROVIDERS[provider]["env_key"]):
        keys = " | ".join(c["env_key"] for c in _PROVIDERS.values())
        # No key configured (e.g. a fork PR, or before setup): skip, don't fail CI.
        print(f"ℹ️  No AI API key found ({keys}) — skipping AI test review.")
        return 0
    print(f"🤖 Provider: {provider} | Model: {os.environ.get('AI_MODEL') or _PROVIDERS[provider]['default_model']}")
    print(f"📦 Project: {cfg['project']} | {cfg['language']} / {cfg['framework']} | glob: {cfg['source_glob']}")

    # 1. diff
    print(f"🔍 Diff: {args.base_ref}..{args.head_ref}")
    diff, changed = get_diff(args.base_ref, args.head_ref, cfg["source_glob"])
    if not diff.strip():
        print("ℹ️  No changes under the source glob — skipping.")
        return 0
    print(f"   Changed: {[f.name for f in changed]}")

    # 2. generate
    print("🤖 Requesting test generation...")
    source   = read_source(changed)
    test_dir = PROJECT_ROOT / cfg["test_dir"]
    existing = read_existing_tests(test_dir, cfg["test_ext"])
    test_code = extract_code_block(generate_tests(cfg, diff, source, existing), cfg["code_fence"])
    if not test_code:
        print("⚠️  Model produced no test code — skipping.")
        return 0

    # 3. write
    test_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = cfg["test_ext"]
    test_file = test_dir / f"test_ai_{ts}{ext if ext.startswith('.') or ext.startswith('_') else '.' + ext}"
    header = (f"# AI-generated {datetime.now():%Y-%m-%d %H:%M} — diff "
              f"{args.base_ref}..{args.head_ref} — review before committing\n")
    test_file.write_text(header + "\n" + test_code, encoding="utf-8")
    print(f"✅ Wrote {test_file.relative_to(PROJECT_ROOT)}")

    if args.dry_run:
        print("🔵 --dry-run: not running.")
        return 0

    # 4. run + robust review loop
    print("\n🧪 Running tests...")
    exit_code, output = run_tests(cfg, test_file)
    print(output)

    attempts = 0
    while exit_code != 0:
        analysis = classify_failure(cfg, source, test_code, output)
        cls  = analysis.get("classification", "test_bug")
        conf = analysis.get("confidence", 0)
        print(f"🔎 Classification: {cls} ({conf:.0%}) — {analysis.get('reason', '')}")

        if cls == "source_bug":
            report = write_bug_report(cfg, analysis, test_file, output)
            print(f"🐛 Real source bug. Wrote {report.relative_to(PROJECT_ROOT)}")
            return 1  # signal true positive to CI

        # test_bug: regenerate the whole file, retry
        if attempts >= MAX_RETRIES:
            print(f"⚠️  Test still broken after {MAX_RETRIES} fix attempts — "
                  "not a source bug, discarding generated file.")
            test_file.unlink(missing_ok=True)
            return 0
        attempts += 1
        print(f"🔧 Fixing test file (attempt {attempts}/{MAX_RETRIES})...")
        fixed = extract_code_block(fix_test_file(cfg, test_code, output, source), cfg["code_fence"])
        if not fixed:
            print("⚠️  No fixed file returned — discarding.")
            test_file.unlink(missing_ok=True)
            return 0
        test_code = fixed
        test_file.write_text(header + "\n" + test_code, encoding="utf-8")
        exit_code, output = run_tests(cfg, test_file)
        print(output)

    print("✅ All generated tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
