# ai_testgen — portable AI test generation & review

A single, dependency-light script that watches your source diff, asks an AI to
write tests for the changed code, runs them, and tells real source bugs apart
from broken generated tests. **Nothing is tied to a project or language** — all
of that comes from config.

## Drop-in (3 files)

Copy these into any repo:

| File | Purpose |
|---|---|
| `scripts/ai_testgen.py` | the engine (stdlib + `anthropic`/`openai` SDK only) |
| `.aitestgen.toml` | your repo's config (language, glob, test dir, run cmd) |
| `.github/workflows/ai-testgen.yml` | generic CI wrapper (GitHub Actions) |

Then add **one** provider key as a GitHub Actions secret:
`ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, or `OPENAI_API_KEY`. Optionally set repo
variables `AI_PROVIDER` / `AI_MODEL` to override auto-detection.

Without a key the tool **skips** (exits 0) — safe for forks and pre-setup repos.

## Configure

Edit `.aitestgen.toml` (or use `.aitestgen.json`). Start from a preset
(`python`, `javascript`, `go`) and override what differs:

```toml
language    = "python"
framework   = "pytest"
project     = "My Project"
source_glob = "src/**/*.py"          # git pathspec glob
test_dir    = "tests/generated"
test_ext    = ".py"
mock_libs   = "unittest.mock"
run_cmd     = ["{py}", "-m", "pytest", "{test_path}", "-q"]
install     = "pip install -r requirements.txt pytest"
```

Placeholders in `run_cmd`: `{py}` (this Python), `{test_path}`, `{test_dir}`.

Every field is also overridable via env vars (`AITG_SOURCE_GLOB`,
`AITG_TEST_DIR`, `AITG_RUN_CMD` as a JSON list, `AITG_PROJECT`, …) so you can
drive it from CI without a file.

## Run anywhere (not just GitHub)

The engine is plain CLI — works locally or in any CI:

```bash
ANTHROPIC_API_KEY=sk-... python scripts/ai_testgen.py --base-ref HEAD~1 --head-ref HEAD
python scripts/ai_testgen.py --print-config     # show resolved config
python scripts/ai_testgen.py --dry-run          # generate but don't run
```

## How review works (language-agnostic)

On a failing run the whole runner output + source + generated test go to the AI
classifier, which returns `test_bug` or `source_bug`:

- **test_bug** (bad syntax, won't compile/collect, wrong mock, unrealistic
  assertion) → the file is regenerated and retried up to `AITG_MAX_RETRIES`
  (default 2); if still broken it's discarded and CI stays green.
- **source_bug** → `bug_report.md` is written and the script exits 1, which the
  workflow surfaces as a PR comment / issue and a failed check.

This is why there is no pytest-specific output parsing: adding a language is just
a new config/preset (run command + fence), not new parsing code.

## Adding a language

Add a block to `PRESETS` in `ai_testgen.py`, or just set the fields in your
config. A preset needs: `language`, `framework`, `source_glob`, `test_dir`,
`test_ext`, `code_fence`, `run_cmd`, `install`, and `detect_files` (for
auto-detection). For non-Python targets, add the toolchain setup step
(`actions/setup-node`, `actions/setup-go`, …) to the workflow.
