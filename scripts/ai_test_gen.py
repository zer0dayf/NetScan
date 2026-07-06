#!/usr/bin/env python3
"""
AI-Powered Test Generation & Review Pipeline
=============================================
GitHub Actions tarafından çağrılır. Adımlar:

1. git diff ile değişen netscan/ dosyalarını tespit et
2. AI API'ye diff + kaynak kodu gönder → yeni test case'leri al
3. tests/generated/test_ai_<timestamp>.py dosyasına yaz
4. pytest çalıştır
5. Başarısız testler varsa AI'a gönder:
   - False positive → AI testi düzeltir, tekrar çalışır
   - True positive  → bug_report.md yaz, exit(1) ile GH Actions'a bildir

Desteklenen AI sağlayıcıları (AI_PROVIDER env var):
  anthropic  → ANTHROPIC_API_KEY   (varsayılan: claude-sonnet-4-6)
  deepseek   → DEEPSEEK_API_KEY    (varsayılan: deepseek-chat)
  openai     → OPENAI_API_KEY      (varsayılan: gpt-4o)

Kullanım:
  AI_PROVIDER=deepseek DEEPSEEK_API_KEY=sk-... python scripts/ai_test_gen.py
  python scripts/ai_test_gen.py [--base-ref HEAD~1] [--head-ref HEAD]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import textwrap
from datetime import datetime
from pathlib import Path

# ── Sabitler ──────────────────────────────────────────────────────────────────

PROJECT_ROOT   = Path(__file__).parent.parent
NETSCAN_PKG    = PROJECT_ROOT / "netscan"
TESTS_DIR      = PROJECT_ROOT / "tests"
GENERATED_DIR  = TESTS_DIR / "generated"
MAX_RETRIES    = 2          # False positive düzeltme deneme sayısı
MAX_DIFF_CHARS = 12_000     # Uzun diff'leri kırp
MAX_SRC_CHARS  = 8_000      # Kaynak dosya başına

# ── AI Provider seçimi ────────────────────────────────────────────────────────

_PROVIDERS = {
    "anthropic": {
        "env_key":     "ANTHROPIC_API_KEY",
        "default_model": "claude-sonnet-4-6",
        "pip_pkg":     "anthropic",
    },
    "deepseek": {
        "env_key":     "DEEPSEEK_API_KEY",
        "default_model": "deepseek-chat",
        "pip_pkg":     "openai",   # DeepSeek, OpenAI-compatible API kullanır
        "base_url":    "https://api.deepseek.com",
    },
    "openai": {
        "env_key":     "OPENAI_API_KEY",
        "default_model": "gpt-4o",
        "pip_pkg":     "openai",
    },
}


def _detect_provider() -> str:
    """Ortam değişkenlerine göre sağlayıcıyı otomatik seçer."""
    explicit = os.environ.get("AI_PROVIDER", "").lower()
    if explicit in _PROVIDERS:
        return explicit
    # Hangi API key set edilmişse onu kullan
    for name, cfg in _PROVIDERS.items():
        if os.environ.get(cfg["env_key"]):
            return name
    return "anthropic"  # fallback


# ── Git diff ──────────────────────────────────────────────────────────────────

def get_diff(base_ref: str, head_ref: str) -> tuple[str, list[Path]]:
    """
    Değişen netscan/ Python dosyalarının diff'ini döner.
    (diff_text, changed_files) tuple'ı döner.
    """
    try:
        raw = subprocess.check_output(
            ["git", "diff", base_ref, head_ref, "--", "netscan/*.py"],
            cwd=PROJECT_ROOT, stderr=subprocess.DEVNULL, text=True,
        )
    except subprocess.CalledProcessError:
        return "", []

    # Hangi dosyalar değişti?
    try:
        changed = subprocess.check_output(
            ["git", "diff", "--name-only", base_ref, head_ref, "--", "netscan/*.py"],
            cwd=PROJECT_ROOT, stderr=subprocess.DEVNULL, text=True,
        ).strip().splitlines()
    except subprocess.CalledProcessError:
        changed = []

    files = [PROJECT_ROOT / f for f in changed if (PROJECT_ROOT / f).exists()]
    return raw[:MAX_DIFF_CHARS], files


def read_source(paths: list[Path]) -> str:
    """Değişen kaynak dosyalarının içeriğini birleştirir."""
    parts = []
    for p in paths:
        try:
            content = p.read_text(encoding="utf-8")[:MAX_SRC_CHARS]
            parts.append(f"# === {p.name} ===\n{content}")
        except OSError:
            pass
    return "\n\n".join(parts)


def read_existing_tests() -> str:
    """Mevcut test dosyalarını (generated/ hariç) döner — context için."""
    parts = []
    for tf in sorted(TESTS_DIR.glob("test_*.py")):
        try:
            parts.append(f"# === {tf.name} ===\n{tf.read_text(encoding='utf-8')[:4000]}")
        except OSError:
            pass
    return "\n\n".join(parts)


# ── AI API ────────────────────────────────────────────────────────────────────

def call_ai(system: str, user: str, temperature: float = 0.2,
            provider: str | None = None, model: str | None = None,
            max_tokens: int = 4096) -> str:
    """
    Aktif sağlayıcıya göre AI API'yi çağırır.
    Anthropic SDK veya OpenAI-compatible SDK (DeepSeek, OpenAI) kullanır.
    """
    provider = provider or _detect_provider()
    cfg      = _PROVIDERS[provider]
    api_key  = os.environ.get(cfg["env_key"])
    if not api_key:
        raise RuntimeError(
            f"'{cfg['env_key']}' ortam değişkeni bulunamadı.\n"
            f"Kullanım: {cfg['env_key']}=<key> python scripts/ai_test_gen.py"
        )
    model = model or os.environ.get("AI_MODEL") or cfg["default_model"]

    if provider == "anthropic":
        try:
            import anthropic as _ant
        except ImportError:
            print("❌ pip install anthropic")
            sys.exit(1)
        client = _ant.Anthropic(api_key=api_key)
        msg    = client.messages.create(
            model=model, max_tokens=max_tokens, temperature=temperature,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return msg.content[0].text

    else:  # deepseek / openai — her ikisi de openai-compatible
        try:
            from openai import OpenAI
        except ImportError:
            print("❌ pip install openai")
            sys.exit(1)
        kw: dict = {"api_key": api_key}
        if "base_url" in cfg:
            kw["base_url"] = cfg["base_url"]
        client = OpenAI(**kw)
        resp   = client.chat.completions.create(
            model=model, max_tokens=max_tokens, temperature=temperature,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        )
        return resp.choices[0].message.content


def extract_python_block(text: str) -> str:
    """
    ```python ... ``` bloğunu çıkarır; yoksa tüm metni döner.
    Kapanış fence'i bulunamazsa (ör. yanıt max_tokens'ta kesildiyse) açılıştan
    sonraki her şeyi en iyi çaba ile döner — exception fırlatıp pipeline'ı
    çökertmek yerine.
    """
    if "```python" in text:
        start = text.index("```python") + len("```python")
        end   = text.find("```", start)
        return text[start:end if end != -1 else None].strip()
    if "```" in text:
        start = text.index("```") + 3
        end   = text.find("```", start)
        return text[start:end if end != -1 else None].strip()
    return text.strip()


# ── Test üretimi ──────────────────────────────────────────────────────────────

SYSTEM_TEST_GEN = textwrap.dedent("""
    Sen bir uzman Python test mühendisisin. NetScan adlı bir LAN ağ tarayıcısı
    projesi için pytest test case'leri yazıyorsun.

    KURALLAR:
    - Sadece ağ erişimi gerektirmeyen unit testler yaz (socket, scapy, requests'i mock'la)
    - Her test fonksiyonu bağımsız çalışabilmeli
    - unittest.mock, pytest.fixture ve parametrize kullan
    - Sadece değişen / eklenen fonksiyonları test et
    - Mevcut testleri KOPYALAMA, onlara tamamlayıcı testler yaz
    - Başarı, hata ve edge case senaryolarını kapsla
    - Testlerin başında import satırlarını ekle
    - SADECE geçerli Python kodu döndür, açıklama metni yazma
""").strip()


def generate_tests(diff: str, source: str, existing_tests: str) -> str:
    user = textwrap.dedent(f"""
        Aşağıdaki git diff'i incele. Değişen / eklenen fonksiyonlar için
        pytest test case'leri yaz.

        ## GIT DIFF
        ```diff
        {diff}
        ```

        ## DEĞİŞEN KAYNAK DOSYALAR
        ```python
        {source}
        ```

        ## MEVCUT TESTLER (bunları tekrar yazma)
        ```python
        {existing_tests[:6000]}
        ```

        Yeni test case'lerini Türkçe değil İngilizce isimlendirme ile,
        ```python ... ``` bloğu içinde döndür.
    """).strip()
    return call_ai(SYSTEM_TEST_GEN, user, max_tokens=8192)


# ── Test çalıştırma ───────────────────────────────────────────────────────────

def run_pytest(test_file: Path) -> tuple[int, str]:
    """pytest çalıştırır. (exit_code, output) döner."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(test_file), "-v", "--tb=short",
         "--no-header", "-q"],
        capture_output=True, text=True, cwd=PROJECT_ROOT,
    )
    return result.returncode, result.stdout + result.stderr


def parse_failures(output: str) -> list[dict]:
    """
    pytest çıktısının 'short test summary info' bölümündeki
    'FAILED path::test - HataTürü: mesaj' satırlarından başarısız test
    bilgilerini çıkarır. Hata mesajı aynı satırda (' - ' sonrası) geldiği için
    onu da yakalıyoruz; aksi halde classify_failure boş bir hata metniyle
    çalışırdı.
    """
    failures = []
    lines    = output.splitlines()
    current: dict | None = None

    for line in lines:
        if line.startswith("FAILED "):
            if current:
                failures.append(current)
            rest = line[len("FAILED "):]
            name, _, brief = rest.partition(" - ")
            current = {"name": name.strip(), "error": [brief] if brief else []}
        elif current and line.strip() and not line.startswith("="):
            # "===== N failed, M passed ====" gibi özet satırlarını hariç tut
            current["error"].append(line)

    if current:
        failures.append(current)

    return failures


# ── Hata sınıflandırma ve düzeltme ───────────────────────────────────────────

SYSTEM_CLASSIFY = textwrap.dedent("""
    Sen bir senior Python test mühendisisin. Bir pytest test başarısızlığını
    inceliyorsun. Görevin şu soruyu yanıtlamak:

    Bu başarısızlık:
    A) FALSE POSITIVE — Testin kendisi yanlış yazılmış (kaynak kod doğru)
    B) TRUE POSITIVE  — Kaynak kodda gerçek bir bug var

    Yanıtını SADECE şu JSON formatında ver (başka hiçbir şey yazma):
    {
      "classification": "false_positive" | "true_positive",
      "confidence": 0.0-1.0,
      "reason": "kısa açıklama",
      "bug_description": "bug açıklaması (sadece true_positive ise)"
    }
""").strip()


def classify_failure(failure: dict, source: str, test_code: str) -> dict:
    user = textwrap.dedent(f"""
        ## BAŞARISIZ TEST
        Test adı: {failure['name']}
        Hata:
        {chr(10).join(failure['error'][:30])}

        ## KAYNAK KOD
        ```python
        {source[:6000]}
        ```

        ## TEST KODU
        ```python
        {test_code[:4000]}
        ```

        Bu başarısızlık false positive mi yoksa true positive mi?
        JSON formatında yanıtla.
    """).strip()

    raw = call_ai(SYSTEM_CLASSIFY, user, temperature=0.1)
    try:
        # JSON bloğunu çıkar
        if "```json" in raw:
            s = raw.index("```json") + 7
            e = raw.index("```", s)
            raw = raw[s:e]
        elif "{" in raw:
            s = raw.index("{")
            e = raw.rindex("}") + 1
            raw = raw[s:e]
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {
            "classification": "unknown",
            "confidence": 0.0,
            "reason": "JSON ayrıştırma hatası",
            "raw": raw,
        }


# ── False positive düzeltmesi (tam dosya) ──────────────────────────────────────

SYSTEM_FIX_FILE = textwrap.dedent("""
    Sen bir senior Python test mühendisisin. Elindeki pytest test dosyasında
    bazı testler false positive olarak işaretlendi — yani testin kendisi yanlış
    yazılmış (yanlış import, yanlış mock hedefi, gerçekçi olmayan assertion vb.),
    kaynak koddaki fonksiyonlar doğru çalışıyor.

    KURALLAR:
    - SADECE listelenen başarısız testleri düzelt
    - Zaten geçen diğer testlere DOKUNMA, aynen koru
    - Dönen dosya baştan sona geçerli, tek parça, collectlenebilir bir Python
      dosyası olmalı — parça/snippet değil, TÜM dosya
    - Gerekli tüm import'lar dosyanın başında tek sefer bulunmalı
    - SADECE geçerli Python kodu döndür, açıklama metni yazma
""").strip()


def fix_test_file(test_code: str, failures: list[dict], source: str) -> str:
    """
    Verilen false-positive başarısızlıkları, orijinal test dosyasının TAMAMI
    bağlamında düzeltir ve tam, geçerli bir dosya olarak geri döner.
    İzole düzeltme parçalarını elle birleştirmekten (kırılgan) kaçınmak için
    tek bir AI çağrısıyla bütün dosyayı yeniden ürettiriyoruz.
    """
    failure_summary = "\n\n".join(
        f"### {f['name']}\n" + "\n".join(f["error"][:15])
        for f in failures
    )
    user = textwrap.dedent(f"""
        ## MEVCUT TEST DOSYASI (TAMAMI)
        ```python
        {test_code}
        ```

        ## FALSE POSITIVE OLARAK İŞARETLENEN BAŞARISIZ TESTLER VE HATALARI
        {failure_summary}

        ## KAYNAK KOD (referans için)
        ```python
        {source[:6000]}
        ```

        Yukarıdaki dosyada sadece listelenen testleri düzelt, geri kalanı aynen
        koru. Düzeltilmiş TAM dosyayı ```python ... ``` bloğu içinde döndür.
    """).strip()
    return call_ai(SYSTEM_FIX_FILE, user, max_tokens=8192)


# ── Collection / sözdizimi hatası onarımı ─────────────────────────────────────

_COLLECTION_ERROR_MARKERS = (
    "during collection",
    "errors during collection",
    "Interrupted:",
    "SyntaxError",
    "IndentationError",
    "ERROR ",  # pytest collection satırı: "ERROR path::..."
)


def is_collection_error(output: str) -> bool:
    """
    pytest çıktısının bir collection/sözdizimi hatası (üretilen dosya hiç
    import/parse edilemedi) olup olmadığını anlar. Bu durumda ortada hiç
    'FAILED' satırı olmaz — hata kaynak kodda değil, AI'nin ürettiği dosyada
    (kapanmayan string, bozuk decorator, hatalı mock hedefi vb.) demektir.
    """
    return any(marker in output for marker in _COLLECTION_ERROR_MARKERS)


SYSTEM_FIX_SYNTAX = textwrap.dedent("""
    Sen bir senior Python test mühendisisin. Ürettiğin pytest test dosyası hiç
    çalıştırılamadı çünkü pytest onu TOPLAYAMADI (collection error) — dosyada bir
    sözdizimi/import hatası var (ör. kapanmayan string literal, bozuk @patch
    decorator, hatalı girinti, geçersiz mock hedefi). Bu bir kaynak-kod bug'ı
    DEĞİL; sadece test dosyasının kendisi bozuk.

    KURALLAR:
    - Testlerin ORİJİNAL amacını koru; sadece dosyayı geçerli hale getir.
    - Dönen dosya baştan sona geçerli, tek parça, collectlenebilir bir Python
      dosyası olmalı — parça/snippet değil, TÜM dosya.
    - @patch/@patch.dict gibi decorator'ları doğru sözdizimiyle yaz.
    - Gerekli tüm import'lar dosyanın başında tek sefer bulunmalı.
    - SADECE geçerli Python kodu döndür, açıklama metni yazma.
""").strip()


def fix_syntax_file(test_code: str, pytest_output: str, source: str) -> str:
    """
    Collection/sözdizimi hatası veren üretilmiş test dosyasını, pytest'in
    verdiği hata mesajı bağlamında geçerli ve collectlenebilir tam bir dosyaya
    dönüştürür.
    """
    error_excerpt = "\n".join(pytest_output.splitlines()[-40:])
    user = textwrap.dedent(f"""
        ## BOZUK TEST DOSYASI (TAMAMI)
        ```python
        {test_code}
        ```

        ## PYTEST COLLECTION HATASI
        ```
        {error_excerpt}
        ```

        ## KAYNAK KOD (referans için)
        ```python
        {source[:6000]}
        ```

        Yukarıdaki dosyanın sözdizimi/collection hatasını düzelt. Düzeltilmiş
        TAM dosyayı ```python ... ``` bloğu içinde döndür.
    """).strip()
    return call_ai(SYSTEM_FIX_SYNTAX, user, max_tokens=8192)


# ── Bug raporu ────────────────────────────────────────────────────────────────

def write_bug_report(bugs: list[dict], test_file: Path) -> Path:
    report_path = PROJECT_ROOT / "bug_report.md"
    lines = [
        "## 🐛 NetScan AI Test Review — Bug Report",
        "",
        f"**Tarih:** {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**Test dosyası:** `{test_file.relative_to(PROJECT_ROOT)}`  ",
        f"**Bulunan bug sayısı:** {len(bugs)}",
        "",
        "---",
        "",
    ]
    for i, bug in enumerate(bugs, 1):
        lines += [
            f"### Bug #{i}: `{bug['failure']['name']}`",
            "",
            f"**Güven skoru:** {bug['analysis'].get('confidence', 0):.0%}",
            "",
            f"**Açıklama:**  ",
            bug["analysis"].get("bug_description", "—"),
            "",
            "**Test hatası:**",
            "```",
            "\n".join(bug["failure"]["error"][:15]),
            "```",
            "",
            "---",
            "",
        ]
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


# ── Ana akış ──────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="AI Test Generation Pipeline")
    parser.add_argument("--base-ref", default="HEAD~1",
                        help="Git diff base referansı (varsayılan: HEAD~1)")
    parser.add_argument("--head-ref", default="HEAD",
                        help="Git diff head referansı (varsayılan: HEAD)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Test üretir ama çalıştırmaz")
    args = parser.parse_args()

    provider = _detect_provider()
    cfg      = _PROVIDERS[provider]
    api_key  = os.environ.get(cfg["env_key"])
    if not api_key:
        keys = " | ".join(f"{c['env_key']}" for c in _PROVIDERS.values())
        print(f"❌ API key bulunamadı. Gerekli: {keys}")
        print(f"   Aktif sağlayıcı: {provider} → {cfg['env_key']}")
        return 1
    model = os.environ.get("AI_MODEL") or cfg["default_model"]
    print(f"🤖 AI Sağlayıcı: {provider} | Model: {model}")

    # ── 1. Diff al ────────────────────────────────────────────────────────────
    print(f"🔍 Git diff: {args.base_ref}..{args.head_ref}")
    diff, changed_files = get_diff(args.base_ref, args.head_ref)

    if not diff.strip():
        print("ℹ️  netscan/ altında değişiklik yok — atlanıyor.")
        return 0

    print(f"   Değişen dosyalar: {[f.name for f in changed_files]}")

    # ── 2. Test üret ──────────────────────────────────────────────────────────
    print("🤖 Claude'a test case üretimi isteği gönderiliyor...")
    source         = read_source(changed_files)
    existing_tests = read_existing_tests()
    raw_tests      = generate_tests(diff, source, existing_tests)
    test_code      = extract_python_block(raw_tests)

    if not test_code or "def test_" not in test_code:
        print("⚠️  Claude test case üretemedi — diff çok küçük olabilir.")
        return 0

    # ── 3. Dosyaya yaz ────────────────────────────────────────────────────────
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    test_file = GENERATED_DIR / f"test_ai_{ts}.py"

    header = textwrap.dedent(f"""
        # AI tarafından üretildi — {datetime.now().strftime('%Y-%m-%d %H:%M')}
        # Diff: {args.base_ref}..{args.head_ref}
        # Değişen: {', '.join(f.name for f in changed_files)}
        # Bu dosyayı commit etmeden önce gözden geçir.
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    """).strip()

    test_file.write_text(header + "\n\n" + test_code, encoding="utf-8")
    print(f"✅ Test dosyası yazıldı: {test_file.relative_to(PROJECT_ROOT)}")

    if args.dry_run:
        print("🔵 --dry-run modunda çıkılıyor.")
        return 0

    # ── 4. Testleri çalıştır ──────────────────────────────────────────────────
    print("\n🧪 pytest çalışıyor...")
    exit_code, output = run_pytest(test_file)
    print(output)

    # ── 4b. Collection/sözdizimi hatası: üretilen dosya bozuk (kaynak bug değil) ─
    # 'FAILED' satırı yokken pytest yine de fail ettiyse dosya hiç toplanamamış
    # demektir; AI ile sözdizimini onarıp tekrar dene, olmazsa dosyayı at.
    syntax_attempts = 0
    while exit_code != 0 and not parse_failures(output) and is_collection_error(output):
        if syntax_attempts >= 2:
            print("⚠️  Üretilen test dosyası onarılamadı (sözdizimi/collection hatası).")
            print("   Bu bir kaynak-kod bug'ı değil — dosya atlanıyor.")
            test_file.unlink(missing_ok=True)
            return 0
        syntax_attempts += 1
        print(f"\n🔧 Collection/sözdizimi hatası — AI ile onarılıyor "
              f"(deneme {syntax_attempts}/2)...")
        fixed_code = extract_python_block(fix_syntax_file(test_code, output, source))
        if not fixed_code or "def test_" not in fixed_code:
            print("⚠️  Onarılmış dosya alınamadı — dosya atlanıyor.")
            test_file.unlink(missing_ok=True)
            return 0
        test_code = fixed_code
        test_file.write_text(header + "\n\n" + test_code, encoding="utf-8")
        exit_code, output = run_pytest(test_file)
        print(output)

    if exit_code == 0:
        print("✅ Tüm testler geçti.")
        return 0

    # ── 5. Başarısız testleri sınıflandır ────────────────────────────────────
    failures = parse_failures(output)
    if not failures:
        print("⚠️  pytest başarısız ama ayrıştırılabilir hata bulunamadı.")
        return exit_code

    print(f"\n🔎 {len(failures)} başarısız test analiz ediliyor...")

    true_positives           = []
    false_positive_failures  = []

    for failure in failures:
        print(f"   → {failure['name']}")
        analysis = classify_failure(failure, source, test_code)
        cls       = analysis.get("classification", "unknown")
        conf      = analysis.get("confidence", 0)
        print(f"     Sınıflandırma: {cls} (güven: {conf:.0%})")

        if cls == "false_positive":
            false_positive_failures.append(failure)
            print("     ⚠️  Test hatası (false positive) — dosya toplu düzeltilecek.")

        elif cls == "true_positive":
            true_positives.append({"failure": failure, "analysis": analysis})
            print(f"     🐛 Gerçek bug: {analysis.get('bug_description','')[:80]}")

    # ── 6. False positive'ler varsa TÜM dosyayı tek seferde düzelt ────────────
    # Not: true_positive'lerin testleri burada dokunulmadan dosyada kalır, bu
    # yüzden aşağıdaki rerun gerçek bir bug'ı asla "geçti" gibi göstermez.
    if false_positive_failures:
        print(f"\n🔁 {len(false_positive_failures)} false positive test düzeltiliyor (tam dosya)...")
        fixed_raw  = fix_test_file(test_code, false_positive_failures, source)
        fixed_code = extract_python_block(fixed_raw)

        if fixed_code and "def test_" in fixed_code:
            test_file.write_text(header + "\n\n" + fixed_code, encoding="utf-8")
            rc2, out2 = run_pytest(test_file)
            print(out2)
            if rc2 == 0:
                print("✅ Düzeltme sonrası tüm testler geçti.")
                return 0
            print("⚠️  Düzeltme sonrası hâlâ başarısız test(ler) var — devam ediliyor.")
        else:
            print("⚠️  Düzeltilmiş dosya alınamadı, orijinal dosya korunuyor.")

    # ── 7. True positive bug'ları raporla ────────────────────────────────────
    if true_positives:
        report = write_bug_report(true_positives, test_file)
        print(f"\n🐛 Bug raporu: {report.relative_to(PROJECT_ROOT)}")
        print("   GitHub Actions bu raporu PR yorumu olarak ekleyecek.")
        return 1  # GH Actions'ı başarısız olarak işaretle

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
