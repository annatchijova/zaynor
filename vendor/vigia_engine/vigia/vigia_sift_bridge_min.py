# NOTE (corrected 2026-07-26): this IS the active MCP bridge -- launch_vigia_mcp.sh
# execs this exact file (vigia/vigia_sift_bridge.py). An earlier version of this
# comment claimed a separate vigia/vigia_sift_bridge_final.py was the active bridge
# and this file was import-path-only; that file does not exist anywhere in the
# repository (confirmed by exhaustive search) and never has, going back through the
# available git history. This file is also the import path used by vigia/__init__.py
# and internal modules -- there is only one bridge file, not three.

"""
VIGÍA — Intentionality Analysis Bridge for SIFT Workstation
============================================================
Author      : Anna Tchijova
License     : Apache 2.0

Theoretical foundation:
  - Charles S. Peirce (Semiotics / Abductive reasoning)
  - Dale Carnegie (Influence / Manipulation patterns)
  - H. Paul Grice (Cooperative Principle / Maxims)
  - Umberto Eco (Overinterpretation / Red Herring detection)

"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import sys
import tempfile
import inspect
from collections import Counter
from functools import wraps
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from vigia.phonetic_loader import PHONETIC_MAP, HIGH_RISK_SET
from vigia.config import CONFIG, LLMBackend
from vigia.security import (
    audit_logger,
    llm_shield,
    _sanitize_path,
    _truncate,
    _utcnow as _utcnow_security,
    rate_limit,
)
from vigia.security.sandbox import sandboxed_execute, safe_grep, _sanitize_grep_pattern

_CRITICAL_STDLIB_FUNCS = {
    "os.open": os.open,
    "os.stat": os.stat,
    "os.lstat": os.lstat,
    "hashlib.sha256": hashlib.sha256,
    "json.dumps": json.dumps,
    "json.loads": json.loads,
    "re.compile": re.compile,
    "math.sqrt": math.sqrt,
}

def _verify_stdlib_integrity() -> dict:
    """
    Verifica que funciones críticas de stdlib no fueron monkey-patched.
    Retorna {"integrity_ok": bool, "violations": list}.
    """
    violations = []
    for name, expected in _CRITICAL_STDLIB_FUNCS.items():
        module_name, func_name = name.rsplit(".", 1)
        mod = __import__(module_name, fromlist=[func_name])
        actual = getattr(mod, func_name)
        if actual is not expected:
            violations.append(name)
    return {
        "integrity_ok": len(violations) == 0,
        "violations": violations,
    }

# ─────────────────────────────────────────────────────────────────────────────
# SERVER INIT
# ─────────────────────────────────────────────────────────────────────────────

mcp = FastMCP("Vigia_Sift_Bridge")

MAX_TEXT_LENGTH    = 50_000   # 50 KB por texto individual
MAX_TEXTS_IN_LIST  = 20       # máximo ítems por llamada de lista
MAX_TOTAL_BYTES    = 500_000  # 500 KB total por llamada
MAX_FILE_PREVIEW   = 100_000  # máximo bytes de preview de archivo

# Los eventos TOOL_INVOKED deben demostrar que una herramienta fue llamada sin
# copiar evidencia potencialmente sensible al audit trail. Para strings, el
# digest cubre como máximo este prefijo y el evento declara si quedó truncado;
# jamás se escanea un payload entero sólo para registrar su invocación.
_AUDIT_ARGUMENT_PREFIX_BYTES = 4096


def _audit_argument_value(value: object) -> str:
    """Return a bounded, non-plaintext description of an MCP argument."""
    if isinstance(value, str):
        encoded = value.encode("utf-8", errors="replace")
        prefix = encoded[:_AUDIT_ARGUMENT_PREFIX_BYTES]
        suffix = ", truncated=true" if len(encoded) > len(prefix) else ""
        return (
            f"str(bytes={len(encoded)}, sha256_prefix="
            f"{hashlib.sha256(prefix).hexdigest()}{suffix})"
        )
    if isinstance(value, bytes):
        prefix = value[:_AUDIT_ARGUMENT_PREFIX_BYTES]
        suffix = ", truncated=true" if len(value) > len(prefix) else ""
        return (
            f"bytes(length={len(value)}, sha256_prefix="
            f"{hashlib.sha256(prefix).hexdigest()}{suffix})"
        )
    if isinstance(value, dict):
        return f"dict(items={len(value)})"
    if isinstance(value, (list, tuple, set, frozenset)):
        return f"{type(value).__name__}(items={len(value)})"
    if value is None or isinstance(value, (bool, int, float)):
        return repr(value)
    return type(value).__name__


def _audit_argument_summary(func, args: tuple, kwargs: dict) -> str:
    """Bind call arguments for audit context without retaining their plaintext."""
    try:
        bound = inspect.signature(func).bind_partial(*args, **kwargs)
        bound.apply_defaults()
        values = bound.arguments.items()
    except TypeError:
        values = tuple((f"arg_{index}", value) for index, value in enumerate(args))
        values += tuple((name, value) for name, value in kwargs.items())
    return "; ".join(
        f"{name}={_audit_argument_value(value)}" for name, value in values
    ) or "no_arguments"


def _audit_mcp_entry(func):
    """Record every MCP tool entry before rate limits or tool execution."""
    @wraps(func)
    async def _audited(*args, **kwargs):
        audit_logger.log_info(
            event_type="TOOL_INVOKED",
            tool=func.__name__,
            message=_audit_argument_summary(func, args, kwargs),
        )
        result = func(*args, **kwargs)
        if inspect.isawaitable(result):
            return await result
        return result

    return _audited


def _register_mcp_tool(func):
    """Register an MCP tool through the mandatory entry-audit boundary."""
    return mcp.tool()(_audit_mcp_entry(func))

# H4/TANDA 2: MAX_PATTERN_LENGTH y _ALLOWED_PATTERN se movieron con la
# función canónica a vigia.security.sandbox (MAX_GREP_PATTERN_LENGTH,
# _ALLOWED_GREP_PATTERN) — una sola fuente para el contrato del validador.


# _sanitize_path viene de vigia.security (version completa con null byte,
# tilde, blocked prefixes, base_dir confinement y must_exist).
# La alias local mantiene compatibilidad con el codigo que ya usa _sanitize_path
# sin argumentos nombrados.
def _sanitize_path_local(path: str) -> str:
    """Constrain a forensic read to evidence or a controlled mounted volume.

    ``VIGIA_EVIDENCE_DIR`` is the immutable input root. A mounted image is
    materialized below the separate work root, but must remain reachable by
    the same read-only MCP tools. Select the matching root before invoking the
    canonical sanitizer so a legitimate mounted path does not create a
    spurious traversal event against the evidence root.
    """
    try:
        candidate = Path(path).resolve(strict=False)
    except (OSError, RuntimeError, TypeError):
        candidate = None
    if candidate is not None:
        for root in (EVIDENCE_BASE_DIR, _MOUNT_ROOT):
            try:
                candidate.relative_to(Path(root).resolve(strict=False))
            except ValueError:
                continue
            return _sanitize_path(path, base_dir=root)
    # Preserve the canonical sanitizer's detailed fail-closed error and audit
    # event for a path outside either authorised read root.
    return _sanitize_path(path, base_dir=EVIDENCE_BASE_DIR)

def _sanitize_text(text: str, max_length: int = MAX_TEXT_LENGTH) -> str:
    """Trunca y castea input para prevenir ReDoS y OOM."""
    return _truncate(text, max_bytes=max_length)


def _sanitize_text_list(texts: list) -> list:
    """Valida y limpia una lista de textos. Previene ataques OOM."""
    if not isinstance(texts, list):
        raise ValueError("Expected a list of texts.")
    if len(texts) > MAX_TEXTS_IN_LIST:
        raise ValueError(f"Too many texts. Maximum allowed: {MAX_TEXTS_IN_LIST}")
    total = sum(len(t.encode("utf-8")) for t in texts if isinstance(t, str))
    if total > MAX_TOTAL_BYTES:
        raise ValueError(f"Total volume exceeds limit of {MAX_TOTAL_BYTES} bytes.")
    return [_sanitize_text(t) for t in texts]


# H4 / TANDA 2 (2026-07-06): _sanitize_grep_pattern vive en
# vigia.security.sandbox (fuente única, fail-closed). La copia local era una
# de dos implementaciones divergentes con el mismo nombre — la del sandbox
# mutaba el patrón silenciosamente (strip NUL + truncado). Se conserva el
def _utcnow() -> str:
    # Alias local para no romper el código existente que la llama sin imports.
    # La función canónica vive en vigia.security.
    return _utcnow_security()

_EVIDENCE_ENV = os.getenv("VIGIA_EVIDENCE_DIR", "").strip()
if _EVIDENCE_ENV:
    # V-004 fix: validate that the configured evidence dir is not a symlink
    # and does not contain path traversal components.
    _evidence_path = Path(_EVIDENCE_ENV)
    if ".." in _evidence_path.parts:
        print(
            f"[VIGIA][CRITICAL] VIGIA_EVIDENCE_DIR contains '..': {_EVIDENCE_ENV!r}. "
            "Refusing to start.",
            file=sys.stderr, flush=True,
        )
        sys.exit(1)
    if _evidence_path.is_symlink():
        print(
            f"[VIGIA][CRITICAL] VIGIA_EVIDENCE_DIR is a symlink: {_EVIDENCE_ENV!r}. "
            "Evidence base directory cannot be a symlink — it is the trust anchor "
            "for all path confinement. Refusing to start.",
            file=sys.stderr, flush=True,
        )
        sys.exit(1)
    # Resolve and verify consistency
    _resolved_evidence = str(_evidence_path.resolve())
    if _resolved_evidence != str(_evidence_path.absolute()):
        print(
            f"[VIGIA][CRITICAL] VIGIA_EVIDENCE_DIR has intermediate symlinks: "
            f"{_EVIDENCE_ENV!r} resolves to {_resolved_evidence!r}. Refusing to start.",
            file=sys.stderr, flush=True,
        )
        sys.exit(1)
    EVIDENCE_BASE_DIR = _EVIDENCE_ENV
else:
    import tempfile as _tempfile
    EVIDENCE_BASE_DIR = _tempfile.mkdtemp(prefix="vigia_evidence_")
    os.chmod(EVIDENCE_BASE_DIR, 0o700)
    print(
        f"[VIGIA] WARNING: VIGIA_EVIDENCE_DIR not set. "
        f"Using secure temp dir: {EVIDENCE_BASE_DIR}\n"
        f"Set VIGIA_EVIDENCE_DIR for production use.",
        file=sys.stderr, flush=True,
    )

def _resolve_work_root() -> str:
    """Return a private operational root that cannot overlap evidence.

    Honey tokens, quarantine copies, and mount points are VIGÍA-generated
    state. Placing any of them under ``VIGIA_EVIDENCE_DIR`` changes a forensic
    input tree before analysis. A caller can configure durable state with
    ``VIGIA_WORK_DIR``; otherwise a mode-0700 temporary root is used.
    """
    configured = os.getenv("VIGIA_WORK_DIR", "").strip()
    if not configured:
        root = tempfile.mkdtemp(prefix="vigia_work_")
        os.chmod(root, 0o700)
        return root

    candidate = Path(configured)
    if "\x00" in configured or ".." in candidate.parts:
        print(
            "[VIGIA][CRITICAL] VIGIA_WORK_DIR contains an unsafe path component. "
            "Refusing to start.",
            file=sys.stderr,
            flush=True,
        )
        sys.exit(1)
    try:
        raw_absolute = candidate.absolute()
        resolved = candidate.resolve(strict=False)
        evidence_root = Path(EVIDENCE_BASE_DIR).resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        print(
            f"[VIGIA][CRITICAL] Cannot resolve VIGIA_WORK_DIR: {exc}. Refusing to start.",
            file=sys.stderr,
            flush=True,
        )
        sys.exit(1)

    # Validate before mkdir: an unsafe configuration must not create even one
    # directory below evidence. Reject symlinked components as well, so a
    # visually separate work path cannot resolve into forensic input.
    if (
        resolved != raw_absolute
        or resolved == evidence_root
        or resolved.is_relative_to(evidence_root)
        or evidence_root.is_relative_to(resolved)
    ):
        print(
            "[VIGIA][CRITICAL] VIGIA_WORK_DIR must be a non-symlink root "
            "disjoint from VIGIA_EVIDENCE_DIR. Refusing to start.",
            file=sys.stderr,
            flush=True,
        )
        sys.exit(1)
    try:
        os.makedirs(raw_absolute, mode=0o700, exist_ok=True)
        os.chmod(raw_absolute, 0o700)
    except OSError as exc:
        print(
            f"[VIGIA][CRITICAL] Cannot create VIGIA_WORK_DIR: {exc}. Refusing to start.",
            file=sys.stderr,
            flush=True,
        )
        sys.exit(1)
    return str(raw_absolute)


# B-173: evidence is read-only; all VIGÍA-created state is work state.
WORK_BASE_DIR = _resolve_work_root()

# P0 FIX: Honey token directory - secure file storage.
_HONEY_TOKEN_DIR = os.path.join(WORK_BASE_DIR, "honey_tokens")
os.makedirs(_HONEY_TOKEN_DIR, exist_ok=True)
os.chmod(_HONEY_TOKEN_DIR, 0o700)  # Owner only

# Purgatorio Forense: cuarentena de evidencia malformada
# Permisos 0o700: solo el proceso VIGIA puede leer/escribir.
# B-173: never below immutable evidence; WORK_BASE_DIR is 0o700 and disjoint.
_PURGATORY_DIR = os.path.join(WORK_BASE_DIR, "purgatory")
os.makedirs(_PURGATORY_DIR, exist_ok=True)
os.chmod(_PURGATORY_DIR, 0o700)  # Owner only

# B-164/B-173: mounted evidence must be reachable by controlled read tools but
# cannot be materialized inside immutable input. _sanitize_path_local accepts
# only EVIDENCE_BASE_DIR or this private mount subtree.
_MOUNT_ROOT = os.path.join(WORK_BASE_DIR, "mounted")
os.makedirs(_MOUNT_ROOT, mode=0o700, exist_ok=True)
os.chmod(_MOUNT_ROOT, 0o700)
_MOUNT_LEAF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
def _word_search(term: str, text: str) -> bool:
    """
    Search for term in text with intelligent boundary detection.

    Gemini fix: \b (word boundary) fails on terms with non-alphanumeric
    characters like [ERROR], (warning), #tag. For these, we use
    start-of-line/space/end-of-line boundaries instead.

    Examples:
      _word_search("[ERROR]", "found [ERROR] in log")  -> True
      _word_search("error", "found [ERROR] in log")    -> True (case handled by caller)
      _word_search("err", "found error in log")        -> False (\b prevents substring)
    """
    stripped = term.strip()
    if not stripped:
        return False
    # Detect if the term contains non-word characters (anything \b can't handle)
    has_special = bool(re.search(r'[^\w]', stripped))
    escaped = re.escape(stripped)
    if has_special:
        # Use whitespace/line boundaries instead of \b
        pattern = r'(?:^|(?<=\s))' + escaped + r'(?=\s|$)'
    else:
        pattern = r'\b' + escaped + r'\b'
    return bool(re.search(pattern, text, re.IGNORECASE))
# SYSTEM PROMPT — PEIRCE REASONING ENGINE (Prompt Vault)
# ─────────────────────────────────────────────────────────────────────────────
# Gemini P0: The system prompt is operational intelligence. It MUST NOT live
# in source code where git history, ps aux, or /proc/*/cmdline can leak it.
# Loaded from a protected file with permission and integrity checks.

# Default prompt path: vigia/data/system_prompt_peirce.md
# Override: VIGIA_SYSTEM_PROMPT_PATH env var
_SYSTEM_PROMPT_PATH_DEFAULT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "data", "system_prompt_peirce.md",
)

# SHA-256 of the canonical prompt. Update after editing the prompt file:
#   sha256sum vigia/data/system_prompt_peirce.md
# Set to "" to skip integrity check (development only).
_SYSTEM_PROMPT_EXPECTED_HASH = os.getenv("VIGIA_PROMPT_HASH", "")


def _load_system_brain() -> str:
    """
    Load the Peirce system prompt from a protected vault file.

    Security checks:
    1. File must exist and be readable
    2. File permissions must be 0600 or 0640 (owner-only write)
    3. File must not be a symlink
    4. If VIGIA_PROMPT_HASH is set, SHA-256 must match (integrity)
    5. If any check fails AND VIGIA_STRICT_PROMPT=true, abort startup

    Returns the prompt text, or a hardcoded minimal fallback in dev mode.
    """
    prompt_path = os.getenv("VIGIA_SYSTEM_PROMPT_PATH", "").strip() or _SYSTEM_PROMPT_PATH_DEFAULT
    strict = os.getenv("VIGIA_STRICT_PROMPT", "false").lower() == "true"

    def _fail(reason: str) -> str:
        audit_logger.log_block(
            event_type="PROMPT_VAULT_FAILURE",
            tool="_load_system_brain",
            input_preview=prompt_path,
            reason=reason,
        )
        if strict:
            print(
                f"[VIGIA][CRITICAL] Prompt vault failure: {reason}. "
                "VIGIA_STRICT_PROMPT=true — aborting.",
                file=sys.stderr, flush=True,
            )
            sys.exit(1)
        print(
            f"[VIGIA][WARNING] Prompt vault: {reason}. Using minimal fallback.",
            file=sys.stderr, flush=True,
        )
        return _FALLBACK_PROMPT

    # Check existence
    if not os.path.exists(prompt_path):
        return _fail(f"Prompt file not found: {prompt_path}")

    # Symlink check
    if os.path.islink(prompt_path):
        return _fail(f"Prompt file is a symlink: {prompt_path}")

    # Permission check (POSIX only)
    if os.name != "nt":
        import stat
        st = os.stat(prompt_path)
        mode = stat.S_IMODE(st.st_mode)
        # Allow 0o600 (owner rw) or 0o640 (owner rw + group r)
        if mode & 0o077 not in (0o000, 0o040):
            return _fail(
                f"Prompt file has insecure permissions: {oct(mode)}. "
                "Expected 0600 or 0640."
            )

    # Read content
    try:
        with open(prompt_path, "r", encoding="utf-8") as fh:
            content = fh.read()
    except OSError as exc:
        return _fail(f"Cannot read prompt file: {exc}")

    if not content.strip():
        return _fail("Prompt file is empty")

    # Integrity check
    if _SYSTEM_PROMPT_EXPECTED_HASH:
        actual_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if actual_hash != _SYSTEM_PROMPT_EXPECTED_HASH:
            return _fail(
                f"Prompt file SHA-256 mismatch. "
                f"Expected: {_SYSTEM_PROMPT_EXPECTED_HASH[:16]}... "
                f"Got: {actual_hash[:16]}... "
                "File may have been tampered with."
            )

    audit_logger.log_info(
        event_type="PROMPT_VAULT_LOADED",
        tool="_load_system_brain",
        message=f"System prompt loaded from {prompt_path} ({len(content)} bytes)",
    )
    return content


# Minimal fallback prompt for development (no cases, no sensitive logic)
_FALLBACK_PROMPT = (
    "You are VIGIA, a forensic analyst. Reason using Peirce semiotics "
    "(Firstness/Secondness/Thirdness). Return JSON with: verdict, confidence, "
    "peirce_chain, signals, narrative. Verdicts: NOISE/SUSPICION/INTENT/MALICE."
)

# Load at module init — fails fast if strict mode is on
SYSTEM_PROMPT_PEIRCE = _load_system_brain()
RUSSIAN_PHONETIC_MAP = PHONETIC_MAP
HIGH_RISK_PHONETIC   = HIGH_RISK_SET

# El veredicto final lo emite el pipeline de analisis — la ingesta no
# condena; preserva y alerta.
# =============================================================================

class _IntegrityViolation(ValueError):
    """Excepcion especializada para violaciones de integridad de lectura.
    Distinguible de otros ValueError — permite enrutamiento al Purgatorio
    sin capturar errores de path o permisos en el mismo bloque.
    """


async def _quarantine_malformed_evidence(
    source_path: str,
    failure_reason: str,
) -> dict:
    """
    Sella evidencia malformada en el Purgatorio Forense.

    OOM-SAFE (auditoria Kimi): hash y escritura en chunks de 4 MB.
    Nunca se carga el archivo completo en memoria — solo el chunk activo
    existe en RAM en cada iteracion. Critico para archivos de evidencia
    grandes (dumps de memoria, imagenes forenses) que podrian activar el
    OOM Killer si se leyeran como raw_bytes de una sola vez.

    Garantias:
    - SHA-256 calculado en streaming sobre el archivo original — el hash
      corresponde exactamente a lo que estaba en disco al momento del fallo.
    - Escritura al Purgatorio tambien en chunks — mismo patron, sin buffer.
    - Archivo de cuarentena sellado con 0o400 (owner read-only) post-escritura.
    - Si la escritura falla, el evento CRITICO se registra igualmente.
    - I/O corre en executor — no bloquea el event loop.

    Args:
        source_path:    Ruta del archivo malformado (se re-abre para streaming).
        failure_reason: Descripcion del error de parseo/decodificacion.

    Returns:
        dict con metadato de cuarentena listo para inyectar al pipeline.
    """
    _CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB — nunca mas de esto en RAM a la vez

    write_success = False
    write_error = None
    raw_hash = "HASH_UNAVAILABLE"
    total_bytes = 0
    # Nombre provisional del archivo de cuarentena — se renombra post-hash
    purgatory_tmp = os.path.join(_PURGATORY_DIR, f"quarantine_inprogress_{os.getpid()}.raw")
    purgatory_path = purgatory_tmp  # se actualizara al conocer el hash

    def _stream_hash_and_write():
        """
        Lectura, hash y escritura en chunks de 4 MB.
        Un solo pass sobre el archivo — eficiente en I/O y OOM-safe.

        TOCTOU hardening (NIGHTFALL P0-1):
        El archivo temporal se crea con mkstemp() — nombre unico e
        impredecible, nunca colisiona con un archivo existente.
        Antes del rename() se verifica que el temporal no fue convertido
        en symlink por un atacante local en la ventana entre escritura
        y rename. Si se detecta symlink: _IntegrityViolation inmediata.
        """
        nonlocal raw_hash, total_bytes, purgatory_path, purgatory_tmp

        sha = hashlib.sha256()

        # mkstemp garantiza nombre unico e impredecible — elimina la
        # ventana de race condition en la creacion del temporal.
        # fd_dst queda abierto; lo usamos directamente para escritura.
        fd_dst, purgatory_tmp = tempfile.mkstemp(
            suffix=".raw",
            prefix="quarantine_inprogress_",
            dir=_PURGATORY_DIR,
        )
        fd_src = -1
        try:
            fd_src = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd_src, "rb", closefd=True) as src, \
                 os.fdopen(fd_dst, "wb", closefd=True) as dst:
                fd_src = -1  # fdopen toma ownership
                fd_dst = -1  # fdopen toma ownership
                for chunk in iter(lambda: src.read(_CHUNK_SIZE), b""):
                    sha.update(chunk)
                    dst.write(chunk)
                    total_bytes += len(chunk)
                # Sellado 0o400 SOBRE EL DESCRIPTOR, no sobre el nombre.
                # os.chmod(path) resuelve el nombre y SIGUE symlinks: si un
                # atacante local sustituye el temporal por un symlink despues
                # del chequeo islink() de mas abajo (check-by-name clasico),
                # un chmod por ruta aplicaria 0o400 al objetivo del symlink —
                # un archivo arbitrario del uid propietario. fchmod actua
                # sobre el inodo que realmente escribimos, sin ventana.
                dst.flush()
                os.fchmod(dst.fileno(), 0o400)
        finally:
            if fd_src >= 0:
                os.close(fd_src)
            if fd_dst >= 0:
                os.close(fd_dst)

        # Hash disponible solo despues de leer todo el archivo
        raw_hash = sha.hexdigest()

        # TOCTOU check: verificar que el temporal no fue convertido en
        # symlink por un atacante local en la ventana entre escritura
        # y rename. os.lstat() no sigue symlinks — ve el nodo real.
        if os.path.islink(purgatory_tmp):
            try:
                os.unlink(purgatory_tmp)
            except OSError:
                pass
            raise _IntegrityViolation(
                f"TOCTOU detected: temporary file {purgatory_tmp!r} was "
                "converted to a symlink between write and rename. "
                "Local attacker with write access to purgatory directory. "
                "Quarantine operation aborted."
            )

        # Renombrar al hash final — nombre canonico en el Purgatorio
        final_path = os.path.join(_PURGATORY_DIR, f"{raw_hash}.raw")
        os.rename(purgatory_tmp, final_path)
        # El modo 0o400 (owner read-only, inmutable post-escritura) ya fue
        # sellado con fchmod() sobre el descriptor antes del cierre — no se
        # re-aplica por ruta aqui para no reintroducir la ventana chmod-sigue-
        # symlink que el fchmod cierra.
        purgatory_path = final_path

    # Estado del timeout — se determina en el except
    _timeout_triggered = False

    try:
        loop = asyncio.get_event_loop()
        async with asyncio.timeout(60):  # 60s: archivos grandes legitimos pueden tardar
            await loop.run_in_executor(None, _stream_hash_and_write)
        write_success = True
    except TimeoutError:
        # PARCHE 1 — Efecto Embudo: el archivo excedio el tiempo de procesamiento.
        # Un archivo desproporcionado o zip-bomb puede paralizar el Purgatorio
        # dejando el proceso en un limbo sin registro forense.
        # Estrategia: preservar el fragmento parcial ya escrito con sufijo .timeout,
        # emitir veredicto INTENT inmediato, y continuar — nunca quedar bloqueados.
        _timeout_triggered = True
        purgatory_timeout_path = purgatory_tmp.replace(
            "quarantine_inprogress_", f"quarantine_timeout_"
        ) + ".timeout"
        try:
            if os.path.exists(purgatory_tmp) and os.path.getsize(purgatory_tmp) > 0:
                os.rename(purgatory_tmp, purgatory_timeout_path)
                os.chmod(purgatory_timeout_path, 0o400)
                purgatory_path = purgatory_timeout_path
            elif os.path.exists(purgatory_tmp):
                os.unlink(purgatory_tmp)
        except OSError:
            pass
        write_error = "TIMEOUT_60s: archivo desproporcionado o zip-bomb"
        audit_logger.log_block(
            event_type="PURGATORY_TIMEOUT_INTENT",
            tool="_quarantine_malformed_evidence",
            input_preview=source_path[:200],
            reason=(
                f"EVIDENCE_TAMPERING_TIMEOUT: procesamiento de {source_path!r} "
                f"excedio 60s. Bytes procesados antes del timeout: {total_bytes}. "
                "Archivo desproporcionado o zip-bomb. "
                "Intencion deliberada de obstruccion fisica (Denial of Service). "
                f"Fragmento parcial preservado en: {purgatory_path}."
            ),
        )
    except Exception as exc:
        write_error = f"{type(exc).__name__}: {exc}"
        try:
            if os.path.exists(purgatory_tmp):
                os.unlink(purgatory_tmp)
        except OSError:
            pass

    # Registro critico en audit trail — inviolable independientemente del
    # exito de la escritura al Purgatorio.
    _event_type = "PURGATORY_TIMEOUT_INTENT" if _timeout_triggered else "PURGATORY_EVIDENCE_QUARANTINED"
    _verdict_signal = "INTENT"  # invariante: toda evidencia malformada o en timeout es INTENT
    audit_logger.log_block(
        event_type=_event_type,
        tool="_quarantine_malformed_evidence",
        input_preview=source_path[:200],
        reason=(
            f"Evidencia malformada interceptada en {source_path!r}. "
            f"Razon de fallo: {failure_reason}. "
            f"SHA-256 raw (streaming): {raw_hash}. "
            f"Bytes procesados: {total_bytes}. "
            f"Escritura al Purgatorio: {'OK' if write_success else 'PARTIAL/FAILED: ' + str(write_error)}. "
            f"Purgatorio: {purgatory_path}. "
            f"Timeout activado: {_timeout_triggered}. "
            "Cadena de custodia preservada."
        ),
    )

    _forensic_alert = (
        f"[PURGATORY_FORENSE - TIMEOUT]: "
        f"Archivo desproporcionado en {source_path!r}. "
        "EVIDENCE_TAMPERING_TIMEOUT: Intencion deliberada de obstruccion "
        "(Denial of Service). Fragmento parcial sellado en Purgatorio."
    ) if _timeout_triggered else (
        f"[PURGATORY_FORENSE]: Evidencia malformada interceptada. "
        f"Posible intento de corrupcion de parser. "
        f"Payload sellado bajo hash {raw_hash}. "
        "El pipeline de analisis debe evaluar este metadato como senal de INTENT."
    )

    return {
        "purgatory_status"  : "TIMEOUT_PARTIAL" if _timeout_triggered else "QUARANTINED",
        "source_path"       : source_path,
        "raw_sha256"        : raw_hash,
        "purgatory_path"    : purgatory_path if (write_success or _timeout_triggered) else "WRITE_FAILED",
        "purgatory_write"   : "TIMEOUT_PARTIAL" if _timeout_triggered else ("OK" if write_success else f"FAILED: {write_error}"),
        "failure_reason"    : failure_reason,
        "raw_size_bytes"    : total_bytes,
        "timeout_triggered" : _timeout_triggered,
        "timestamp"         : _utcnow(),
        "forensic_alert"    : _forensic_alert,
        "verdict_signal"    : _verdict_signal,
        "reason"            : "EVIDENCE_TAMPERING_TIMEOUT - Archivo desproporcionado o zip-bomb. "
                              "Intencion deliberada de obstruccion fisica (Denial of Service)."
                              if _timeout_triggered else failure_reason,
    }


def _honey_meta_path(token_path: str) -> str:
    return token_path + ".meta.json"


def _sweep_expired_honey_tokens() -> list:
    """B9 (A-2): retiro perezoso de tokens vencidos. Un token con sidecar
    .meta.json cuyo expires_at quedó en el pasado se retira CON auditoría;
    sin sidecar, el token no expira (compatibilidad con los previos)."""
    removed = []
    try:
        entries = sorted(os.listdir(_HONEY_TOKEN_DIR))
    except OSError:
        return removed
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)  # CI-EXEMPT: honey token TTL, not in verdict path
    for name in entries:
        if not name.endswith(".meta.json"):
            continue
        meta_path = os.path.join(_HONEY_TOKEN_DIR, name)
        token_path = meta_path[: -len(".meta.json")]
        try:
            expires_at = json.loads(open(meta_path).read()).get("expires_at")
            if not expires_at:
                continue
            if datetime.fromisoformat(expires_at) <= now:
                for p in (token_path, meta_path):
                    if os.path.exists(p):
                        os.unlink(p)
                removed.append(token_path)
                audit_logger.log_info(
                    event_type="HONEY_TOKEN_EXPIRED",
                    tool="deactivate_honey_token",
                    message=f"Token expirado retirado: {token_path}",
                )
        except (OSError, ValueError) as e:
            audit_logger.log_info(
                event_type="HONEY_TOKEN_SWEEP_ERROR",
                tool="deactivate_honey_token",
                message=f"Sweep no pudo procesar {meta_path}: {e}",
            )
    return removed


def _deactivate_honey_token_impl(file_path: str) -> dict:
    """B9 (A-2): retiro de un token CON auditoría y contención estricta —
    NO es un rm arbitrario: realpath dentro de _HONEY_TOKEN_DIR y basename
    honey_* obligatorios (sin traversal, sin symlink escape)."""
    real = os.path.realpath(file_path)
    honey_root = os.path.realpath(_HONEY_TOKEN_DIR)
    if not (real == honey_root or real.startswith(honey_root + os.sep)) \
            or not os.path.basename(real).startswith("honey_"):
        audit_logger.log_block(
            event_type="HONEY_TOKEN_DEACTIVATE_BLOCKED",
            tool="deactivate_honey_token",
            input_preview=file_path,
            reason="Path fuera de _HONEY_TOKEN_DIR o basename no honey_*",
        )
        return {
            "error": "Path fuera del directorio de honey tokens.",
            "security_block": True,
            "timestamp": _utcnow(),
        }
    if not os.path.isfile(real):
        return {
            "error": f"Token no encontrado: {real}",
            "timestamp": _utcnow(),
        }
    try:
        os.unlink(real)
        meta = _honey_meta_path(real)
        if os.path.exists(meta):
            os.unlink(meta)
    except OSError as e:
        return {"error": f"No se pudo retirar el token: {e}",
                "timestamp": _utcnow()}
    audit_logger.log_info(
        event_type="HONEY_TOKEN_DEACTIVATED",
        tool="deactivate_honey_token",
        message=f"Token retirado con auditoría: {real}",
    )
    return {
        "status": "HONEY_TOKEN_DEACTIVATED",
        "file_path": real,
        "timestamp": _utcnow(),
        "vigia_verdict": (
            f"[VIGIA_VERDICT]: HONEYPOT_RETIRED. Retirar también el watch: "
            f"auditctl -W {real} -p r -k honey_access"
        ),
    }




# ─────────────────────────────────────────────────────────────────────────────
# TOOLS — curated subset (see docs/red-team/2026-09-17-round-17-vendored-mcp-tools.md)
# ─────────────────────────────────────────────────────────────────────────────

@_register_mcp_tool
@rate_limit(max_calls=100, window_seconds=60, raise_on_limit=False)
async def list_files(directory: str = ".") -> list:
    """List files and directories. Entry point for filesystem exploration."""
    try:
        path = _sanitize_path_local(directory)
        return os.listdir(path)
    except (ValueError, OSError) as e:
        return [f"ERROR: {str(e)}"]


@_register_mcp_tool
@rate_limit(max_calls=100, window_seconds=60, raise_on_limit=False)
async def read_evidence(path: str, max_bytes: int = 5000) -> dict:
    """
    Read a file for forensic analysis with atomic hash computation.

    TOCTOU-safe: opens the file descriptor ONCE, uses os.fstat(fd) for
    size validation, then reads + hashes in a single pass. The file
    cannot be swapped between the size check and the read.

    Returns SHA-256 computed over the exact bytes that were read,
    ensuring the hash corresponds to the content in the report.
    """
    try:
        path = _sanitize_path_local(path)
    except ValueError as e:
        return {"error": str(e)}

    if not os.path.exists(path):
        return {"error": f"File not found: {path}"}

    if not os.path.isfile(path):
        return {"error": f"Path is not a regular file: {path}"}

    MAX_HASH_SIZE = 500 * 1024 * 1024  # 500 MB
    max_bytes = min(max_bytes, MAX_FILE_PREVIEW)
    sha256    = hashlib.sha256()
    preview   = b""
    total     = 0
    file_size = 0

    def _atomic_read():
        """
        Single-open, single-pass read + hash.

        Opens the fd once, stats the fd (not the path — immune to
        symlink swap between stat and open), reads all bytes while
        simultaneously feeding them to SHA-256.
        """
        nonlocal preview, total, file_size
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            stat = os.fstat(fd)
            file_size = stat.st_size
            if file_size > MAX_HASH_SIZE:
                raise ValueError(
                    f"File too large to hash ({file_size} bytes). "
                    f"Limit is {MAX_HASH_SIZE // (1024*1024)} MB."
                )
            with os.fdopen(fd, "rb", closefd=True) as f:
                fd = -1  # fdopen takes ownership
                while True:
                    block = f.read(4096)
                    if not block:
                        break
                    sha256.update(block)
                    remaining = max_bytes - total
                    if remaining > 0:
                        preview += block[:remaining]
                    total += len(block)

                # P0 fix (Kimi 2026-04): verify post-read consistency.
                # If the file was swapped between fstat and read completion,
                # total bytes read will differ from fstat size.
                if total != file_size:
                    raise _IntegrityViolation(
                        f"INTEGRITY VIOLATION: fstat reported {file_size} bytes "
                        f"but read {total} bytes. File may have been modified "
                        f"during read (race condition or active tampering)."
                    )
        finally:
            if fd >= 0:
                os.close(fd)

    try:
        async with asyncio.timeout(30):
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, _atomic_read)

        # Purgatorio Forense: decodificacion estricta — si hay bytes invalidos
        # es señal de corrupcion o payload malicioso. No silenciar con errors="replace".
        try:
            content = preview.decode("utf-8", errors="strict")
        except UnicodeDecodeError as ude:
            return await _quarantine_malformed_evidence(
                source_path=path,
                failure_reason=f"UnicodeDecodeError: {ude}",
            )

        # Zero-byte file detection (Kimi 2026-04)
        forensic_note = (
            "SHA-256 computed atomically during read (single fd, single pass). "
            "Hash corresponds exactly to the bytes processed. "
            "Any future discrepancy invalidates this evidence."
        )
        zero_byte_alert = None
        if total == 0:
            zero_byte_alert = (
                "POTENTIAL_WIPING_INDICATOR: 0-byte file detected. "
                "A file that exists but contains no data may indicate "
                "deliberate evidence destruction (truncation attack). "
                "Cross-reference with filesystem journal and backup timestamps."
            )

        result = {
            "path"            : path,
            "content_preview" : content,
            "bytes_previewed" : len(preview),
            "total_file_size" : total,
            "sha256"          : sha256.hexdigest(),
            "timestamp_read"  : _utcnow(),
            "forensic_note"   : forensic_note,
        }
        if zero_byte_alert:
            result["zero_byte_alert"] = zero_byte_alert
            result["verdict"] = "SUSPICION"
        return result
    except _IntegrityViolation as exc:
        # Violacion de integridad durante lectura — posible tampering activo
        # Re-abre el archivo en streaming para el Purgatorio (OOM-safe)
        return await _quarantine_malformed_evidence(
            source_path=path,
            failure_reason=str(exc),
        )
    except ValueError as exc:
        return {"error": str(exc)}
    except OSError as exc:
        if "Operation not permitted" in str(exc) or exc.errno == 1:
            return {"error": f"O_NOFOLLOW: path is a symlink or permission denied: {exc}"}
        return {"error": f"Cannot open file: {exc}"}


@_register_mcp_tool
@rate_limit(max_calls=30, window_seconds=60, raise_on_limit=False)
async def search_pattern(pattern: str, folder: str = ".") -> dict | str:
    """
    Search for strings using grep with resource sandbox.

    P2 fix (2026-04 audit): replaced direct subprocess.check_output with
    safe_grep() which enforces memory/CPU limits via setrlimit, depth
    limiting, and path confinement to evidence or a controlled mounted volume.
    """
    try:
        pattern = _sanitize_grep_pattern(pattern)
    except ValueError as e:
        return {"error": str(e)}

    result = await safe_grep(
        pattern=pattern,
        folder=folder,
        max_depth=CONFIG.max_grep_depth,
        max_memory_mb=CONFIG.sandbox_memory_mb,
        max_cpu_seconds=CONFIG.sandbox_cpu_seconds,
        allowed_dirs=[EVIDENCE_BASE_DIR, _MOUNT_ROOT],
    )

    if result["error"]:
        return {"status": "ERROR", "error": result["error"], "timestamp": _utcnow()}
    if not result["matches"]:
        return "Search completed with no findings."
    return {
        "status"   : "OK",
        "matches"  : result["matches"],
        "truncated": result["truncated"],
        "count"    : len(result["matches"]),
        "timestamp": _utcnow(),
    }


@_register_mcp_tool
@rate_limit(max_calls=100, window_seconds=60, raise_on_limit=False)
async def generate_forensic_hash(file_path: str) -> dict:
    """
    Generate SHA-256 hash of a file for chain of custody.
    If this hash changes by a single bit, evidence was tampered with.
    """
    try:
        file_path = _sanitize_path_local(file_path)
    except ValueError as e:
        return {"error": str(e)}

    if not os.path.exists(file_path):
        return {"error": "File not found for integrity audit."}

    sha256 = hashlib.sha256()
    try:
        loop = asyncio.get_event_loop()

        def _hash():
            with open(file_path, "rb") as f:
                for block in iter(lambda: f.read(4096), b""):
                    sha256.update(block)

        await loop.run_in_executor(None, _hash)

        return {
            "file"          : os.path.basename(file_path),
            "full_path"     : file_path,
            "sha256"        : sha256.hexdigest(),
            "timestamp"     : _utcnow(),
            "status"        : "INTEGRITY_VERIFIED",
            "forensic_note" : "Store this hash. Any future discrepancy indicates deliberate tampering.",
        }
    except Exception as e:
        return {"error": f"Integrity audit failed: {str(e)}"}


@_register_mcp_tool
@rate_limit(max_calls=10, window_seconds=60, raise_on_limit=False)
async def calculate_shannon_entropy(data: str) -> dict:
    """
    Measure chaos level in a text or payload using Shannon's formula.

    Interpretation ranges:
      3.5 – 5.0  → Normal human text
      5.0 – 6.0  → Suspicious: possible compression or obfuscated code
      6.0 – 8.0  → CRITICAL: encrypted data or malicious payload

    Also detects LOCAL entropy anomalies (hidden encrypted blocks
    within otherwise normal-looking files).

    Peirce Firstness: the raw phenomenon before interpretation.
    """
    data = _sanitize_text(data)
    if not data:
        return {"error": "No data to analyze."}

    def _compute(payload: str) -> dict:
        # ── Global entropy ────────────────────────────────────────────────────
        freq    = Counter(payload)
        length  = len(payload)
        entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())

        # ── Local entropy — detect hidden high-entropy blocks ─────────────────
        block_size    = 256
        local_scores  = []
        max_local_ent = 0.0
        suspicious_blocks = []

        for i in range(0, length, block_size):
            block = payload[i : i + block_size]
            if len(block) < 16:
                continue
            bf  = Counter(block)
            bl  = len(block)
            be  = -sum((c / bl) * math.log2(c / bl) for c in bf.values())
            local_scores.append(be)
            max_local_ent = max(max_local_ent, be)
            if be > 6.5:
                suspicious_blocks.append({
                    "block_offset": i,
                    "block_entropy": round(be, 4),
                    "note": "High-entropy block detected — possible embedded payload.",
                })

        # ── Verdict ───────────────────────────────────────────────────────────
        if entropy > 6.0 or max_local_ent > 6.5:
            interpretation = "CRITICAL: High probability of encrypted or obfuscated data."
            verdict        = "MALICE"
            abduction      = (
                "Abductive hypothesis: this payload is an encrypted tunnel, "
                "an obfuscated executable, or a steganographic carrier."
            )
        elif entropy > 5.0:
            interpretation = "SUSPICIOUS: Possible artificial compression or encoding evasion."
            verdict        = "SUSPICION"
            abduction      = (
                "Abductive hypothesis: the sender is attempting to conceal "
                "the actual content of the message."
            )
        else:
            interpretation = "Normal: consistent with human text or readable code."
            verdict        = "NOISE"
            abduction      = "No abductive hypothesis generated. Entropy within normal parameters."

        return {
            "global_entropy"    : round(entropy, 4),
            "max_local_entropy" : round(max_local_ent, 4),
            "suspicious_blocks" : suspicious_blocks,
            "interpretation"    : interpretation,
            "verdict"           : verdict,
            "abduction"         : abduction,
            "bytes_analyzed"    : length,
            "timestamp"         : _utcnow(),
        }

    return await asyncio.to_thread(_compute, data)


@_register_mcp_tool
@rate_limit(max_calls=30, window_seconds=60, raise_on_limit=False)
async def infer_intent(
    message_history : list,
    prior_context   : str = "",
    suspicious_lang : str = "",
) -> dict:
    """
    Analyze the full trajectory of a conversation to infer the real
    PURPOSE behind messages.

    Detects:
    - Academic Trojan Horse (competence bypass)
    - Gradual escalation (system seduction)
    - Russian phonetic evasion and other linguistic bypasses
    - Carnegie appeals (authority, emotion, flattery)
    - False familiarity (Carnegie Paradox)
    - Significant silence (Eco Filter)

    message_history : list of dicts {"role": "user/assistant", "text": "..."}
    prior_context   : description of the system/host context
    suspicious_lang : language code if foreign text present (e.g. "ru")
    """
    signals      = []
    score        = 0.0

    # PUNTO 5: Validate message_history structure before any processing.
    # A malformed history (not a list, or items that aren't dicts, or dicts
    # missing "role"/"text") would cause a silent KeyError deep in the
    # analysis loops — this guard surfaces it cleanly at the entry point.
    if not isinstance(message_history, list):
        return {"error": "Invalid message_history: expected a list."}
    for i, msg in enumerate(message_history):
        if not isinstance(msg, dict):
            return {"error": f"Invalid message_history: item {i} is not a dict (got {type(msg).__name__})."}
        if "role" not in msg or "text" not in msg:
            return {"error": f"Invalid message_history: item {i} must have 'role' and 'text' keys."}

    user_messages = [m["text"] for m in message_history if m.get("role") == "user"]
    escalation_detected = False

    # ── 1. Authority establishment ────────────────────────────────────────
    authority_markers = [
        "as a researcher", "in my phd", "according to my experience",
        "as an expert", "i work at", "years of experience", "publication",
        "peer review", "my thesis", "laboratory", "university",
        "como investigador", "en mi doctorado", "como experto",
        "trabajo en", "tengo años de", "mi tesis",
    ]
    for idx, msg in enumerate(user_messages):
        hits = [m for m in authority_markers if _word_search(m, msg.lower())]
        if hits:
            score += 15
            signals.append({
                "type"          : "AUTHORITY_ESTABLISHMENT",
                "message_index" : idx,
                "markers"       : hits,
                "interpretation": "User builds credibility before making the real request.",
                "weight"        : 15,
            })

    # ── 2. Carnegie appeals ───────────────────────────────────────────────
    carnegie_patterns = {
        "flattery_to_system": [
            "a model of your caliber", "you are the best", "only you can",
            "your intelligence", "i trust you", "you are different",
            "more advanced than", "capable of understanding",
            "un modelo de tu calibre", "sos el mejor", "solo vos podés",
        ],
        "emotional_appeal": [
            "it is urgent", "my life depends", "i have no one else",
            "it is to save", "please help me", "i am the victim",
            "nobody believes me", "i just need this",
            "es urgente", "mi vida depende", "no tengo a quien más",
        ],
        "lesser_evil_negotiation": [
            "just the theory", "i won't use it", "it's hypothetical",
            "without the dangerous details", "in general terms",
            "just to understand", "i don't need the exact method",
            "solo la teoría", "no voy a usarlo", "es hipotético",
        ],
    }
    for ctype, markers in carnegie_patterns.items():
        for idx, msg in enumerate(user_messages):
            hits = [m for m in markers if _word_search(m, msg.lower())]
            if hits:
                score += 20
                signals.append({
                    "type"          : f"CARNEGIE_{ctype.upper()}",
                    "message_index" : idx,
                    "markers"       : hits,
                    "interpretation": f"Influence technique: {ctype.replace('_', ' ')}",
                    "weight"        : 20,
                })

    # ── 3. False familiarity — Carnegie Paradox ───────────────────────────
    familiarity_markers = [
        "claudito", "amigo", "vos que sabés", "mi querido",
        "buddy", "pal", "my friend", "you know everything",
        "you're smart", "you understand me",
    ]
    sensitive_requests = [
        "/etc/", "kernel", "memdump", "root", "shadow", "/proc/",
        "private key", "credentials", "passwd",
    ]
    for idx, msg in enumerate(user_messages):
        ml       = msg.lower()
        fam_hits = [m for m in familiarity_markers if _word_search(m, ml)]
        sen_hits = [m for m in sensitive_requests if _word_search(m, ml)]
        if fam_hits and sen_hits:
            score += 40
            signals.append({
                "type"          : "FALSE_FAMILIARITY_CARNEGIE_PARADOX",
                "message_index" : idx,
                "familiarity"   : fam_hits,
                "sensitive_refs": sen_hits,
                "interpretation": (
                    "Attacker simulates emotional bond to lower system guard "
                    "while requesting privileged access. Fabricated Thirdness."
                ),
                "weight"        : 40,
            })

    # ── 4. Gradual escalation (system seduction) ──────────────────────────
    if len(user_messages) >= 3:
        lengths = [len(m) for m in user_messages]
        avg_early = sum(lengths[:-1]) / len(lengths[:-1])
        if lengths[-1] > avg_early * 2:
            score += 25
            escalation_detected = True
            signals.append({
                "type"          : "GRADUAL_ESCALATION_DETECTED",
                "pattern"       : "Short setup messages → long final request",
                "lengths"       : lengths,
                "interpretation": "Context-building followed by critical request. System seduction.",
                "weight"        : 25,
            })

    # ── 5. Russian phonetic evasion ───────────────────────────────────────
    full_text = " ".join(user_messages).lower()

    if suspicious_lang == "ru" or re.search(r'[а-яА-ЯёЁ]', full_text):
        for idx, msg in enumerate(user_messages):
            has_cyrillic = bool(re.search(r'[а-яА-ЯёЁ]', msg))
            has_latin    = bool(re.search(r'[a-zA-Z]', msg))
            if has_cyrillic and has_latin:
                score += 20
                signals.append({
                    "type"          : "MIXED_ALPHABET_SUSPICIOUS",
                    "message_index" : idx,
                    "interpretation": (
                        "Cyrillic-Latin mix may indicate filter evasion "
                        "via non-standard transliteration."
                    ),
                    "weight"        : 20,
                })

    for phonetic, real in RUSSIAN_PHONETIC_MAP.items():
        if _word_search(phonetic, full_text):
            weight = 25 if phonetic in HIGH_RISK_PHONETIC else 15
            score += weight
            signals.append({
                "type"          : "RUSSIAN_PHONETIC_EVASION",
                "phonetic_form" : phonetic,
                "actual_word"   : real,
                "interpretation": (
                    "Phonetic writing to evade dictionary-based keyword filters. "
                    "Deliberate effort to bypass detection = demonstrated MALICE."
                ),
                "weight"        : weight,
            })

    # ── 6. Peirce chain ───────────────────────────────────────────────────
    first_msg = user_messages[0] if user_messages else ""
    last_msg  = user_messages[-1] if user_messages else ""

    if score >= 75:
        thirdness = (
            f"Abductive hypothesis: user operates under an 'Evasion Habit'. "
            f"Gradual escalation ({'detected' if escalation_detected else 'not detected'}) "
            f"suggests a predefined objective concealed behind "
            f"{len([s for s in signals if 'AUTHORITY' in s['type']])} authority markers."
        )
    else:
        thirdness = "No rupture of standard communicative habit observed."

    peirce_chain = {
        "firstness" : {
            "description": "Isolated signals observed in first contact",
            "observation": first_msg[:200] + "..." if len(first_msg) > 200 else first_msg,
        },
        "secondness": {
            "description"        : "Relationship of signals to declared context",
            "anomalies_detected" : len(signals),
            "context"            : prior_context if prior_context else "Not provided",
        },
        "thirdness" : {
            "description"    : "Inferred habit / intent from full trajectory",
            "pattern"        : "TROJAN_HORSE" if score > 40 else "NORMAL_BEHAVIOR",
            "abduction"      : thirdness,
            "last_observation": last_msg[:200] + "..." if len(last_msg) > 200 else last_msg,
        },
    }

    probability = min(score / 100.0, 0.99)

    if probability >= 0.70:
        purpose = (
            "COMPETENCE BYPASS: Real objective is extracting restricted information "
            "using academic or emotional authority as disguise."
        )
        action  = (
            "ACTIVATE SEMANTIC HONEYPOT: Request reformulation 3 times. "
            "Record divergence between versions."
        )
        verdict = "MALICE"
    elif probability >= 0.40:
        purpose = "GREY ZONE: Possible evasion intent. Insufficient context to determine malice."
        action  = "APPLY SEMANTIC ATTRITION: Ask for specific purpose of each requested piece of data."
        verdict = "SUSPICION"
    else:
        purpose = "WITHIN PARAMETERS: No significant evasion patterns detected."
        action  = "PASSIVE OBSERVATION."
        verdict = "NOISE"

    vigia = (
        f"[VIGIA_VERDICT]: {verdict}. "
        f"Intent trajectory analysis: {len(signals)} signals detected across "
        f"{len(user_messages)} user messages. "
        f"Evasion probability: {round(probability * 100)}%. "
        f"Carnegie patterns: {len([s for s in signals if 'CARNEGIE' in s['type']])}. "
        f"Purpose assessment: {purpose}"
    )

    return {
        "timestamp"          : _utcnow(),
        "case"               : "INTENT_TRAJECTORY",
        "signals"            : signals,
        "escalation_detected": escalation_detected,
        "score_raw"          : round(score, 1),
        "probability_evasion": round(probability, 2),
        "purpose"            : purpose,
        "suggested_action"   : action,
        "verdict"            : verdict,
        "peirce_chain"       : peirce_chain,
        "vigia_verdict"      : vigia,
    }


@_register_mcp_tool
@rate_limit(max_calls=30, window_seconds=60, raise_on_limit=False)
async def audit_grice_maxims(messages: list) -> dict:
    """
    Analyze violations of Grice's 4 maxims to detect deception.
    Also measures adjective density as an indicator of emotional manipulation.

    1. Quality   : Does it tell the truth or lack evidence?
    2. Quantity  : Too much information (noise) or too little (concealment)?
    3. Relation  : Is it relevant or a distraction?
    4. Manner    : Is it deliberately obscure or ambiguous?
    5. Adjective density: overloaded evaluative language signals manipulation.

    Forensic pragmatics: deception is not in what is said,
    but in how it is said and what is omitted.
    """
    try:
        messages = _sanitize_text_list(messages)
    except ValueError as e:
        return {"error": str(e)}

    if not messages:
        return {"error": "Empty message list."}

    signals      = []
    score        = 0.0
    lengths      = [len(m) for m in messages]

    # ── 1. Maxim of Quantity ──────────────────────────────────────────────
    if any(l > 1000 for l in lengths):
        score += 25
        signals.append({
            "maxim"         : "QUANTITY",
            "type"          : "SATURATION",
            "interpretation": (
                "Excessively long messages. Saturation is a technique to "
                "hide critical data within semantic noise."
            ),
            "weight"        : 25,
        })

    sparse = [m for m in messages if len(m) < 10]
    if len(sparse) > len(messages) * 0.4:
        score += 20
        signals.append({
            "maxim"         : "QUANTITY",
            "type"          : "SCARCITY",
            "interpretation": (
                "Abnormally short responses. "
                "Active concealment produces deliberate scarcity."
            ),
            "weight"        : 20,
        })

    # ── 2. Maxim of Relation (v3.2 — phenomenon-based, bilingual) ──────
    # B-126: v1 used a 15-keyword topic list that fired on ~100% of
    # natural-language testimony (zero discriminating power). v3.2
    # replaces it with four linguistic phenomena that detect real
    # evasion: factual impossibility, quantity asymmetry, evidence
    # withholding, and fundamental ignorance of own identity data.
    # Threshold=25 requires at least 2 weak phenomena or 1 strong
    # one (factual impossibility) — a deliberate Daubert-consistent
    # decision: a single evasion indicator without corroboration
    # stays at INFERRED, not SUSPICION.
    #
    # Negation helpers for EN contracted/uncontracted forms.
    _neg_en = r"(?:do(?:es)?\s*(?:not|n.t)|did\s*(?:not|n.t)|(?:can|could)\s*(?:not|n.t))"
    _neg_es = r"(?:no\s*(?:puede|pudo|sabe|supo|tiene|tuvo|logr[oó]))"

    _full_text = " ".join(messages).lower()
    _evasion_score = 0
    _evasion_details = []

    # 2a. Factual impossibility (EN + ES)
    # PHENOMENON: claims access to someone's activity + evidence that
    # access channels were severed. Order-independent co-occurrence.
    _access_claims_en = [
        r"(?:saw|watched|view\w+|observ\w+|monitor\w+|track\w+|follow\w+)\s.*(?:activit|post|feed|content|message)",
        r"(?:receiv\w+|got|had)\s.*(?:notification|screenshot|capture|alert|update)",
        r"(?:real.time|in\s*real\s*time|live)",
        r"(?:kept\s*seeing|was\s*watching|could\s*see)",
    ]
    _access_claims_es = [
        r"(?:vi[oó]|veía|miraba|observ\w+|monitore\w+|segu[ií]\w*)\s.*(?:actividad|publicaci|contenido|mensaje)",
        r"(?:recibi[oó]|tuvo|tení?a)\s.*(?:notificaci|captura|alerta|aviso)",
        r"(?:tiempo\s*real|en\s*vivo)",
        r"(?:descarg[oó].*material|avis[oó].*en\s*tiempo)",
        r"captura",
    ]
    _access_denials_en = [
        r"(?:block\w+|remov\w+\s.*contact|cut\s*off|no\s*contact|unfriend)",
        r"(?:chang\w+\s.*privac|restrict\w+|bann\w+|no\s*(?:access|channel|connection))",
    ]
    _access_denials_es = [
        r"(?:bloqueado|bloque[oó]|eliminad[oa]|sin\s*contacto|restringid[oa]|sin\s*acceso)",
        r"(?:lo\s*tiene\s*bloqueado|la\s*tiene\s*bloqueada)",
    ]
    _never_met_any = [
        r"(?:never\s*met)", r"(?:nunca\s*conoci[oó]?)", r"(?:no\s*(?:la|lo)\s*conoce)",
        r"(?:" + _neg_en + r"\s*know\s*(?:her|him|them)\s*personally)",
    ]
    _accuse_any = [
        r"(?:harass|threaten|stalk|danger|bother|meddle|afraid|fear|scared)",
        r"(?:acosa|amenaz|molesta|miedo|peligr|se\s*mete|loca)",
    ]
    _nobody_see = [r"(?:nobody\s*(?:outside|can\s*see))", r"(?:nadie\s*(?:fuera|puede\s*ver))"]

    _has_access_claim = (
        any(re.search(p, _full_text) for p in _access_claims_en)
        or any(re.search(p, _full_text) for p in _access_claims_es)
    )
    _has_access_denial = (
        any(re.search(p, _full_text) for p in _access_denials_en)
        or any(re.search(p, _full_text) for p in _access_denials_es)
        or any(re.search(p, _full_text) for p in _nobody_see)
    )
    _has_never_met = any(re.search(p, _full_text) for p in _never_met_any)
    _has_accuse = any(re.search(p, _full_text) for p in _accuse_any)

    if _has_access_claim and _has_access_denial:
        _evasion_score += 25
        _evasion_details.append("factual_impossibility")

    if _has_never_met and _has_accuse:
        if "factual_impossibility" not in _evasion_details:
            _evasion_score += 25
            _evasion_details.append("factual_impossibility")
        else:
            _evasion_score += 10
            _evasion_details.append("impossibility_reinforced")

    # 2b. Quantity asymmetry (EN + ES)
    # PHENOMENON: the actor who performed an action omits/minimizes
    # quantity while a less-involved party states specific amounts.
    _omission_en = [
        _neg_en + r"\s*(?:recall|remember|know)\s*(?:how\s*(?:many|much)|the\s*(?:amount|number|total|quantity))",
        r"(?:declar\w+\s*(?:nothing|no\s*(?:quantity|amount)))",
        _neg_en + r"\s*(?:say|state|mention|declar)\s*(?:how\s*(?:many|much))",
    ]
    _omission_es = [
        r"(?:no\s*declara\s*(?:cantidad|cuánt|monto|total))",
        r"(?:omite|oculta)\s*(?:la\s*)?(?:cantidad|monto)",
        r"(?:no\s*(?:sabe|recuerda|indica)\s*(?:cuánt|la\s*cantidad|el\s*monto))",
        r"(?:activo\s*(?:no\s*declara|omite))",
    ]
    _precision_en = [
        r"\d+\s*(?:gb|mb|tb|files?|transfers?|transactions?|dollars?|euros?)",
        r"(?:one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|twenty|hundred|thousand)"
        r"\s+(?:\w+\s+)?(?:transfer|transaction|file|dollar|euro)",
        r"total(?:ing|ling)\s+[\w\s]*(?:\d+|(?:hundred|thousand))",
    ]
    _precision_es = [
        r"\d+\s*(?:gb|mb|tb|archivos?|transferencias?|veces|pesos|dólares)",
        r"(?:exactamente|precisamente)\s+\d+",
        r"(?:declara|dice|afirma)\s+\d+\s*gb",
        r"(?:periféric\w+|tercero)\s.*\d+\s*gb",
    ]

    _has_omission = (any(re.search(p, _full_text) for p in _omission_en)
                     or any(re.search(p, _full_text) for p in _omission_es))
    _has_precision = (any(re.search(p, _full_text) for p in _precision_en)
                      or any(re.search(p, _full_text) for p in _precision_es))

    if _has_omission and _has_precision:
        _evasion_score += 20
        _evasion_details.append("quantity_asymmetry")

    # 2c. Evidence withholding (EN + ES)
    # PHENOMENON: evidence was claimed to exist but is now unavailable
    # for reasons controlled by the claimant.
    _possession_en = [
        r"(?:took\s*(?:photo|picture|screenshot|video)|sav\w+\s*(?:them|it|the|photo|to))",
        r"(?:record\w+\s*(?:it|the|video|audio)|wrote\s*down)",
        r"(?:receiv\w+\s*(?:screenshot|photo|evidence|proof|copy))",
        r"(?:kept\s*(?:a\s*)?(?:copy|record|backup|log))",
    ]
    _possession_es = [
        r"(?:(?:tomó|sacó|hizo)\s*(?:foto|captura|screenshot|video))",
        r"(?:(?:guardó|salvó|recibió)\s*(?:foto|captura|prueba|copia))",
        r"(?:(?:tenía|tiene)\s*(?:foto|captura|prueba|copia|registro))",
    ]
    _unavail_en = [
        r"(?:(?:is|are|was|were)\s*(?:lost|gone|missing|deleted|corrupted|destroyed))",
        r"(?:(?:got|was|were)\s*(?:reformatt|format|wip|eras|stolen|broken|crash))",
        r"(?:threw\s*(?:it\s*)?away)",
        r"(?:" + _neg_en + r"\s*(?:find|locate|access|recover|produc|present|show|provid))",
        r"(?:did\s*not\s*(?:back|save|keep|preserv))",
    ]
    _unavail_es = [
        r"(?:" + _neg_es + r"\s*(?:presentar|mostrar|producir|exhibir|encontrar))",
        r"(?:(?:se\s*)?(?:perdió|borró|rompió|formateó|desapareció))",
        r"(?:no\s*(?:lo|la|los|las)\s*(?:tiene|tengo|encuentr|conserv))",
        r"(?:no\s*pudo\s*presentar)",
    ]

    _ph = sum(1 for p in _possession_en + _possession_es if re.search(p, _full_text))
    _uh = sum(1 for p in _unavail_en + _unavail_es if re.search(p, _full_text))
    if _ph > 0 and _uh > 0:
        _wh_strength = min(_ph, _uh)
        _wh_score = min(15 + 5 * (_wh_strength - 1), 25)
        _evasion_score += _wh_score
        _evasion_details.append("evidence_withholding")

    # 2d. Fundamental ignorance of own identity data (EN + ES)
    _fund_ig_en = [_neg_en + r"\s*know\s*(?:my|his|her|their)\s*(?:own\s*)?(?:phone|number|address|password|email)"]
    _fund_ig_es = [
        r"no\s*sabe\s*(?:el\s*)?(?:número|teléfono|celular)",
        r"no\s*(?:sabe|conoce)\s*(?:su\s*(?:propio\s*)?)?(?:número|teléfono|celular)",
    ]
    if any(re.search(p, _full_text) for p in _fund_ig_en + _fund_ig_es):
        _evasion_score += 15
        _evasion_details.append("fundamental_ignorance")

    if _evasion_score >= 25:
        score += min(_evasion_score, 30)
        signals.append({
            "maxim"         : "RELATION",
            "type"          : "TACTICAL_EVASION",
            "features"      : _evasion_details,
            "interpretation": (
                "Linguistic evasion phenomena detected: "
                + ", ".join(_evasion_details) + ". "
                "Testimony contains structural contradictions or "
                "strategic information management patterns."
            ),
            "weight"        : min(_evasion_score, 30),
        })

    # ── 3. Maxim of Manner ────────────────────────────────────────────────
    ambiguous = [
        "perhaps", "could be", "someone said", "rumor has it",
        "eventually", "in theory", "supposedly", "they say",
        "quizás", "podría", "alguien dijo", "se rumorea",
        "eventualmente", "en teoría", "supuestamente",
    ]
    amb_hits = sum(1 for m in messages if any(_word_search(p, m.lower()) for p in ambiguous))
    if amb_hits > len(messages) * 0.4:
        score += 20
        signals.append({
            "maxim"         : "MANNER",
            "type"          : "DELIBERATE_AMBIGUITY",
            "interpretation": (
                "High frequency of dubitative expressions. "
                "Systematic ambiguity is a plausible deniability technique."
            ),
            "weight"        : 20,
        })

    # ── 4. Maxim of Quality ───────────────────────────────────────────────
    truth_claims = [
        "trust me", "i swear", "i promise", "it is the truth",
        "i guarantee", "believe me", "i assure you",
        "confíame", "te lo juro", "te prometo", "es la verdad",
        "te lo garantizo", "creeme",
    ]
    qual_hits = sum(1 for m in messages if any(_word_search(p, m.lower()) for p in truth_claims))
    if qual_hits > 0:
        score += 25
        signals.append({
            "maxim"         : "QUALITY",
            "type"          : "OVER_ASSERTION_OF_TRUTHFULNESS",
            "interpretation": (
                "Those who tell the truth rarely need to swear it. "
                "Excessive honesty claims are a classic deception indicator."
            ),
            "weight"        : 25,
        })

    # ── 5. Adjective density — emotional manipulation signal ─────────────
    evaluative_adjectives = [
        "incredible", "amazing", "urgent", "critical", "unique", "perfect",
        "absolute", "total", "complete", "definitive", "irrefutable",
        "obviously", "clearly", "certainly", "undeniably",
        "increíble", "urgente", "crítico", "único", "perfecto",
        "absoluto", "total", "completo", "definitivo", "irrefutable",
        "obviamente", "claramente", "ciertamente",
    ]
    full_text   = " ".join(messages).lower()
    word_count  = len(re.findall(r'\b\w+\b', full_text))
    adj_hits    = sum(len(re.findall(r'\b' + re.escape(a) + r'\b', full_text)) for a in evaluative_adjectives)
    adj_density = adj_hits / word_count if word_count > 0 else 0

    if adj_density > 0.05:
        # B-126: tiered scoring. Extreme adj density (>10%) is a stronger
        # Carnegie signal than moderate (>5%). With v3.2 RELATION no longer
        # acting as a catch-all, adj_density alone must be able to reach
        # SUSPICION (probability >= 0.30) for urgency/authority framing.
        _adj_weight = 30 if adj_density >= 0.10 else 20
        score += _adj_weight
        signals.append({
            "maxim"          : "QUALITY",
            "type"           : "HIGH_EVALUATIVE_ADJECTIVE_DENSITY",
            "adj_density"    : round(adj_density, 4),
            "adj_count"      : adj_hits,
            "total_words"    : word_count,
            "interpretation" : (
                f"Adjective density: {round(adj_density * 100, 1)}% of total words. "
                f"Overloaded evaluative language bypasses rational analysis "
                f"and targets emotional response — Carnegie manipulation."
            ),
            "weight"         : _adj_weight,
        })

    probability = min(score / 100.0, 0.99)

    if probability >= 0.60:
        abduction = (
            "ABDUCTIVE HYPOTHESIS: Grice's Cooperative Principle was systematically violated. "
            "The interlocutor does not seek to inform but to manipulate. "
            "Deception lies not in individual facts but in dialogue structure."
        )
        verdict = "MALICE"
    elif probability >= 0.30:
        abduction = (
            "ABDUCTIVE HYPOTHESIS: Possible Cooperative Principle violations. "
            "May be partial deception, tactical evasion, or poor communication."
        )
        verdict = "SUSPICION"
    else:
        abduction = "Communication within Cooperative Principle. No significant violations detected."
        verdict   = "NOISE"

    vigia = (
        f"[VIGIA_VERDICT]: {verdict}. "
        f"Gricean analysis: {len(signals)} maxim violations detected. "
        f"Deception probability: {round(probability * 100)}%. "
        f"Adjective density: {round(adj_density * 100, 1)}%. {abduction}"
    )

    return {
        "maxims_analyzed"    : 5,
        "messages_analyzed"  : len(messages),
        "signals_detected"   : signals,
        "score_raw"          : round(score, 1),
        "adjective_density"  : round(adj_density, 4),
        "probability_deception": round(probability, 2),
        "abduction"          : abduction,
        "verdict"            : verdict,
        "grice_interpretation": (
            "Interlocutor broke the Cooperative Principle. Not informing — manipulating."
            if probability >= 0.60
            else "Cooperative communication within normal parameters."
        ),
        "timestamp"          : _utcnow(),
        "vigia_verdict"      : vigia,
    }


@_register_mcp_tool
@rate_limit(max_calls=30, window_seconds=60, raise_on_limit=False)
async def detect_eco_overinterpretation(evidence_list: list) -> dict:
    """
    Detect when clues are TOO perfect.

    Umberto Eco: the perfect conspiracy leaves no obvious traces.
    If there are too many, someone planted them (Malice by Distraction).

    Detects forensic Red Herring: manufactured evidence designed
    to divert investigation away from the real trail.

    Also implements the Eco Filter / Significant Silence:
    the absence of expected artifacts is itself evidence.
    """
    try:
        evidence_list = _sanitize_text_list([str(e) for e in evidence_list])
    except ValueError as e:
        return {"error": str(e)}

    # FASE 2 / D1: la lógica pura vive en vigia.core.eco_check (fuente única)
    # — el scorer determinista aplica EXACTAMENTE el mismo criterio a los
    # artefactos exculpatorios antes de apartarlos. Este tool conserva la
    # capa MCP: sanitización, timestamp y narrativa [VIGIA_VERDICT].
    from vigia.core.eco_check import eco_overinterpretation_check

    result = eco_overinterpretation_check(evidence_list)
    result["timestamp"] = _utcnow()
    ratio = result.get("obvious_ratio", 0.0)
    if result["verdict"] == "POSSIBLE_SCENE_STAGING":
        result["vigia_verdict"] = (
            f"[VIGIA_VERDICT]: MALICE_BY_DISTRACTION. "
            f"Eco filter triggered: {round(ratio * 100)}% of evidence contains "
            f"obvious bait terms. Scene staging probability is high. "
            f"Invert analysis — search for significant silence."
        )
    else:
        result.pop("suspicious_evidence", None)  # contrato histórico del tool
        result["vigia_verdict"] = (
            f"[VIGIA_VERDICT]: NOISE. Evidence ratio normal "
            f"({round(ratio * 100)}% obvious terms)."
        )
    return result


@_register_mcp_tool
@rate_limit(max_calls=5, window_seconds=60, raise_on_limit=False)
async def validate_and_correct_analysis(
    evidence      : str,
    prior_analysis: dict,
) -> dict:
    """
    Agent reviews its own analysis looking for Peircean fallacies.
    Implements the self-correction requirement of the SANS hackathon.

    Checks for:
    1. PREMATURE ABDUCTION: skipped Firstness, jumped to conclusions
    2. FALSE SECONDNESS: context used is generic, not host-specific
    3. HABITLESS THIRDNESS: Thirdness not supported by real artifacts
    4. CARNEGIE BIAS: analyst saw manipulation where there was operational error
    """
    evidence       = _sanitize_text(evidence, max_length=5_000)
    analysis_str   = json.dumps(prior_analysis, default=str)[:5_000]

    # CONFUSED DEPUTY FIX: `prior_analysis` is the raw output of upstream
    # MCP tools (infer_intent, audit_grice_maxims, detect_eco_overinterpretation,
    # cross_artifact_analysis, ...) which may echo attacker-controlled evidence
    # content verbatim (e.g. in "interpretation"/"observation"/"vigia_verdict"
    # fields). Those tools do not scan their inputs for prompt injection —
    # only the LLM-facing boundary does. Without this scan, a hostile artifact
    # could ride an upstream tool's output straight into this LLM prompt
    # unfiltered, exactly like it would if it reached reason_with_llm directly.
    try:
        evidence     = llm_shield.scan(evidence,     "validate_and_correct_analysis.evidence")
        analysis_str = llm_shield.scan(analysis_str, "validate_and_correct_analysis.prior_analysis")
    except ValueError as exc:
        return {
            "error": str(exc),
            "security_block": True,
            "self_correction_timestamp": _utcnow(),
        }

    prompt = f"""
Review this forensic analysis for these specific errors:

1. PREMATURE ABDUCTION: Did it skip Firstness and jump to conclusions?
2. FALSE SECONDNESS: Is the "context" used generic or host-specific?
3. HABITLESS THIRDNESS: Is Thirdness supported by real artifacts or speculation?
4. CARNEGIE BIAS: Did the analyst see manipulation where there was operational error?

Analysis to review: {analysis_str}
Original evidence : {evidence}

If you find errors, return the corrected analysis with:
  "correction_applied": true
  "correction_reason": explanation of what failed in original reasoning

If analysis is sound, return it unchanged with:
  "correction_applied": false
  "validation_note": what was verified
"""
    llm = LLMBackend()
    response = await llm.reason(prompt, SYSTEM_PROMPT_PEIRCE)

    if not response:
        return {
            "error"                    : "LLM returned empty response.",
            "llm_backend"              : llm._actual_backend or CONFIG.llm_backend,
            "backend_warn"             : llm._backend_warn,
            "self_correction_timestamp": _utcnow(),
        }

    try:
        clean  = response.strip().removeprefix("```json").removesuffix("```").strip()
        result = json.loads(clean)
        result["self_correction_timestamp"] = _utcnow()
        result["llm_backend"]               = llm._actual_backend or CONFIG.llm_backend
        result["backend_warn"]              = llm._backend_warn
        return result
    except json.JSONDecodeError:
        return {
            "raw_response"             : response[:2000],
            "error"                    : "Model did not return valid JSON.",
            "self_correction_timestamp": _utcnow(),
            "llm_backend"              : llm._actual_backend or CONFIG.llm_backend,
            "backend_warn"             : llm._backend_warn,
        }



if __name__ == "__main__":
    mcp.run()
