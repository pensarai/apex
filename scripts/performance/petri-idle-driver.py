#!/usr/bin/env python3
"""PTY driver for the home idle-animation benchmark (root-owned TUI entry).

Runs the real TUI (via scripts/performance/petri-idle-run.ts) in a 120x35 PTY
through warm/focused/blurred/resized/refocused phases with typing during blur
and refocus, a final providers-dialog phase (the dialog opens over the
still-mounted home view — no non-home timing claim is made from it), and a
reconstructed final screen for input continuity.

Metrics are honest transport-level numbers: per-phase CPU is the whole
process's process.cpuUsage sampled in-process every 250 ms — only sample
intervals lying wholly inside a phase's own start/end are summed and divided
by the included samples' own wall time (sampler overhead: one
appendFileSync per 250 ms). PTY read counts and byte rates are transport
chunks, not renderer frames. Every run is a fresh process under an isolated
HOME with all inherited provider API keys and OTLP variables stripped; the
selected model points at a dead local endpoint, so no live model call can
happen even if a message were submitted accidentally.

Usage:
  python3 scripts/performance/petri-idle-driver.py BASELINE_ROOT CANDIDATE_ROOT PAIRS OUT_DIR
"""

import fcntl
import hashlib
import json
import os
import pty
import re
import select
import shutil
import signal
import statistics
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

ROWS, COLS = 35, 120
RESIZED_ROWS, RESIZED_COLS = 30, 100
SAMPLE_MS = 250
NODE_ENV = "production"

# Phases: (name, pump duration, action) — a phase's window spans its action
# and its pump, so typing/transition work is attributed to its own phase.
PHASES = [
    ("warmup", 4.0, None),
    ("focusedSteady", 10.0, None),
    ("blurredTransition", 1.0, "blur"),
    ("blurredSteady", 8.0, None),
    ("blurredTyped", 1.2, "type-hello"),
    ("blurredResized", 6.0, "resize"),
    ("blurredRestored", 3.0, "restore"),
    ("refocusedTransition", 1.0, "focus"),
    ("refocusedSteady", 8.0, None),
    ("refocusedTyped", 1.2, "type-world"),
    ("providersDialogIdle", 8.0, "open-providers-dialog"),
]

STRIP_ENV_PATTERNS = [
    re.compile(
        r"^(ANTHROPIC|OPENAI|OPENROUTER|GOOGLE_GENERATIVE|BEDROCK|"
        r"CONCENTRATE|INCEPTION|PENSAR|DAYTONA|RUNLOOP|BRAVE)_[A-Z_]*(KEY|TOKEN|SECRET)?$"
    ),
    re.compile(r"^(OTEL_EXPORTER_OTLP|OTEL_SERVICE_NAME|OTEL_RESOURCE_ATTRIBUTES)"),
]

# The home screen's prompt placeholder — proof the home view (and its
# animation) is mounted, unlike startup escapes or diagnostics.
HOME_ANCHOR = "Type a message to start"
# The provider-selection dialog title — proof the providers dialog actually
# opened (the config already has a provider, so the manager skips onboarding).
DIALOG_ANCHOR = "Select provider"
# Steady phases must produce accepted CPU intervals; short transition and
# typing phases are reported but not required to.
REQUIRED_STEADY = {
    "warmup",
    "focusedSteady",
    "blurredSteady",
    "blurredResized",
    "blurredRestored",
    "refocusedSteady",
    "providersDialogIdle",
}

CONFIG = {
    "responsibleUseAccepted": True,
    "anthropicAPIKey": "fixture-key",
    "selectedModelId": "custom:retention:fixture",
    "customProviders": {
        "retention": {
            "baseUrl": "http://127.0.0.1:9/v1",
            "apiKeyEnv": "PETRI_IDLE_FIXTURE_KEY",
            "models": [
                {"id": "fixture", "contextLength": 200000, "maxOutputTokens": 32000}
            ],
        }
    },
}


def stripped_env(home: Path, log: Path) -> dict:
    env = {}
    for name, value in os.environ.items():
        if any(p.match(name) for p in STRIP_ENV_PATTERNS):
            continue
        env[name] = value
    env["HOME"] = str(home)
    env["PETRI_IDLE_LOG"] = str(log)
    env["NODE_ENV"] = NODE_ENV
    return env


def set_winsize(fd: int, rows: int, cols: int) -> None:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


ESCAPE_RE = re.compile(r"\x1b\[([0-9;]*)([A-Za-z])")


def reconstruct_screen(text: str) -> list[list[str]]:
    """Replay absolute-positioned cell writes into a final screen grid.

    The renderer's output is a diff stream of cursor-position (CUP) writes;
    every text cell is written after an explicit position, so a minimal
    replay of CUP plus printable runs reconstructs the visible screen for
    the input-continuity check.
    """
    screen = [[" "] * COLS for _ in range(ROWS)]
    row = col = 0
    pos = 0
    while pos < len(text):
        ch = text[pos]
        if ch == "\x1b":
            match = ESCAPE_RE.match(text, pos)
            if not match:
                pos += 1
                continue
            params, final = match.group(1), match.group(2)
            pos = match.end()
            if final in ("H", "f"):
                parts = params.split(";") if params else []
                r = int(parts[0]) if parts and parts[0] else 1
                c = int(parts[1]) if len(parts) > 1 and parts[1] else 1
                row, col = r - 1, c - 1
            elif final == "J" and (params == "2" or params == ""):
                screen = [[" "] * COLS for _ in range(ROWS)]
            elif final == "K":
                for i in range(col, COLS):
                    if 0 <= row < ROWS:
                        screen[row][i] = " "
            continue
        if ch == "\r":
            col = 0
        elif ch == "\n":
            row += 1
        elif ch >= " ":
            if 0 <= row < ROWS and 0 <= col < COLS:
                screen[row][col] = ch
            col += 1
        pos += 1
    return screen


def run_once(root: Path, out_dir: Path, tag: str) -> dict:
    home = out_dir / f"home-{tag}"
    if home.exists():
        shutil.rmtree(home)
    (home / ".pensar").mkdir(parents=True)
    (home / ".pensar" / "config.json").write_text(json.dumps(CONFIG))
    sample_log = out_dir / f"samples-{tag}.jsonl"
    phase_log = out_dir / f"phases-{tag}.jsonl"
    screen_log = out_dir / f"screen-{tag}.log"
    sample_log.write_text("")

    master, slave = pty.openpty()
    set_winsize(slave, ROWS, COLS)
    child = subprocess.Popen(
        ["bun", "--no-env-file", "scripts/performance/petri-idle-run.ts"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        cwd=root,
        env=stripped_env(home, sample_log),
        start_new_session=True,
    )
    os.close(slave)
    output = bytearray()

    def pump(duration: float) -> tuple[int, int]:
        reads = bytes_read = 0
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            readable, _, _ = select.select([master], [], [], 0.1)
            if not readable:
                continue
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            output.extend(chunk)
            reads += 1
            bytes_read += len(chunk)
        return reads, bytes_read

    def write(data: str) -> None:
        os.write(master, data.encode())

    markers = []
    input_ok = False
    try:
        # Anchor on the home screen's prompt placeholder, not startup
        # escapes: timing starts only once the home view is mounted.
        startup_deadline = time.monotonic() + 45
        while HOME_ANCHOR not in output.decode("utf-8", "replace"):
            if child.poll() is not None:
                screen_log.write_text(output.decode("utf-8", "replace"))
                raise SystemExit(
                    f"TUI exited during startup (code {child.returncode}); "
                    f"output captured in {screen_log}"
                )
            if time.monotonic() > startup_deadline:
                screen_log.write_text(output.decode("utf-8", "replace"))
                raise SystemExit(
                    f"home screen anchor {HOME_ANCHOR!r} not observed within 45s; "
                    f"output captured in {screen_log}"
                )
            pump(0.5)
        for name, duration, action in PHASES:
            start = time.time() * 1000
            if action == "blur":
                write("\x1b[O")
            elif action == "focus":
                write("\x1b[I")
            elif action == "type-hello":
                for ch in "hello":
                    write(ch)
                    time.sleep(0.1)
            elif action == "type-world":
                for ch in "world":
                    write(ch)
                    time.sleep(0.1)
            elif action == "open-providers-dialog":
                # Clear the typed prompt before the slash command, so Enter
                # can only ever execute /providers, never submit a message.
                # The providers command opens a dialog over the still-mounted
                # home view; this phase makes no non-home timing claim.
                dialog_from = len(output)
                for _ in range(10):
                    write("\x7f")
                    time.sleep(0.05)
                for ch in "/providers":
                    write(ch)
                    time.sleep(0.05)
                write("\r")
            elif action == "resize":
                set_winsize(master, RESIZED_ROWS, RESIZED_COLS)
            elif action == "restore":
                set_winsize(master, ROWS, COLS)
            reads, bytes_read = pump(duration)
            markers.append(
                {
                    "phase": name,
                    "start": start,
                    "end": time.time() * 1000,
                    "reads": reads,
                    "readBytes": bytes_read,
                }
            )
            if child.poll() is not None:
                screen_log.write_text(output.decode("utf-8", "replace"))
                raise SystemExit(
                    f"TUI exited during phase {name} (code {child.returncode}); "
                    f"output captured in {screen_log}"
                )
            if name == "refocusedTyped":
                screen = reconstruct_screen(output.decode("utf-8", "replace"))
                prompt_text = " ".join(
                    "".join(row).strip() for row in screen
                ).replace(" ", "")
                input_ok = "helloworld" in prompt_text
            if name == "providersDialogIdle" and DIALOG_ANCHOR not in output[
                dialog_from:
            ].decode("utf-8", "replace"):
                screen_log.write_text(output.decode("utf-8", "replace"))
                raise SystemExit(
                    f"providers dialog anchor {DIALOG_ANCHOR!r} not observed; "
                    f"output captured in {screen_log}"
                )
        text = output.decode("utf-8", "replace")
        screen_log.write_text(text)
        if not input_ok:
            raise SystemExit(
                f"input continuity failed: the reconstructed screen lacks "
                f"the typed prompt text; output captured in {screen_log}"
            )
        # The TUI's observability exit handlers do not always exit on
        # SIGTERM; escalate to SIGKILL rather than abandon the process.
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=10)
        process_cleaned_up = child.poll() is not None
    finally:
        phase_log.write_text("".join(json.dumps(m) + "\n" for m in markers))
        try:
            os.close(master)
        except OSError:
            pass
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass

    samples = [
        json.loads(line) for line in sample_log.read_text().splitlines() if line
    ]
    phases = {}
    for marker in markers:
        # Only sample intervals wholly inside this phase's own window count
        # toward its CPU; the denominator is those samples' own recorded
        # wall durations, not the nominal sampling period.
        rows = [
            s
            for s in samples
            if marker["start"] <= s["startT"] and s["endT"] <= marker["end"]
        ]
        wall_ms = sum(r["wallMs"] for r in rows)
        if not rows and marker["phase"] in REQUIRED_STEADY:
            raise SystemExit(
                f"steady phase {marker['phase']} produced no CPU intervals "
                f"wholly inside its window"
            )
        phases[marker["phase"]] = {
            "samples": len(rows),
            "sampleWallMsTotal": wall_ms,
            "cpuPercent": (
                100.0 * sum(r["cpuUs"] for r in rows) / (wall_ms * 1000)
                if rows
                else None
            ),
            "ptyReadsPerSec": marker["reads"] / ((marker["end"] - marker["start"]) / 1000),
            "ptyBytesPerSec": marker["readBytes"]
            / ((marker["end"] - marker["start"]) / 1000),
        }
    return {
        "tag": tag,
        "root": str(root),
        "nodeEnv": NODE_ENV,
        "command": "bun --no-env-file scripts/performance/petri-idle-run.ts",
        "inputContinuity": input_ok,
        "processCleanedUp": process_cleaned_up,
        "childExit": child.returncode,
        "phases": phases,
    }


# Per-side file hashes: a dirty git head alone cannot identify the
# production source actually measured, so the animation source, the focus
# seam, and the benchmark scripts are hashed per run.
def file_hashes(root: Path) -> dict:
    hashes = {}
    for name, rel in {
        "petriAnimation": "src/tui/components/chat/petri-animation.tsx",
        "terminalFocus": "src/tui/terminal-focus.ts",
        "runner": "scripts/performance/petri-idle-run.ts",
        "driver": "scripts/performance/petri-idle-driver.py",
    }.items():
        data = (root / rel).read_bytes()
        hashes[name] = hashlib.sha256(data).hexdigest()
    return hashes


def git_head(root: Path) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=root
    )
    return proc.stdout.strip() if proc.returncode == 0 else "(git-archive extract)"


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit(__doc__)
    baseline, candidate = Path(sys.argv[1]), Path(sys.argv[2])
    pairs = int(sys.argv[3])
    out_dir = Path(sys.argv[4])
    out_dir.mkdir(parents=True, exist_ok=True)
    heads = {"baseline": git_head(baseline), "candidate": git_head(candidate)}
    source_hashes = {
        "baseline": file_hashes(baseline),
        "candidate": file_hashes(candidate),
    }
    bun_version = subprocess.run(
        ["bun", "--version"], capture_output=True, text=True
    ).stdout.strip()

    runs = []
    for pair in range(pairs):
        first, second = (
            ("baseline", "candidate") if pair % 2 == 0 else ("candidate", "baseline")
        )
        for side in (first, second):
            root = baseline if side == "baseline" else candidate
            tag = f"{side}-{pair}"
            print(f"running {tag} in {root}", flush=True)
            run = run_once(root, out_dir, tag)
            run = {
                "side": side,
                "head": heads[side],
                "sourceHashes": source_hashes[side],
                "bunVersion": bun_version,
                **run,
            }
            runs.append(run)
            print(json.dumps(run), flush=True)

    summary = []
    for phase, _duration, _action in PHASES:
        for side in ("baseline", "candidate"):
            rows = [r["phases"].get(phase) for r in runs if r["side"] == side]
            rows = [r for r in rows if r and r.get("samples")]
            if not rows:
                continue
            summary.append(
                {
                    "phase": phase,
                    "side": side,
                    "runs": len(rows),
                    "cpuPercentMedian": statistics.median(
                        r["cpuPercent"] for r in rows
                    ),
                    "ptyReadsPerSecMedian": statistics.median(
                        r["ptyReadsPerSec"] for r in rows
                    ),
                    "ptyBytesPerSecMedian": statistics.median(
                        r["ptyBytesPerSec"] for r in rows
                    ),
                }
            )
    input_ok = {
        side: all(r["inputContinuity"] for r in runs if r["side"] == side)
        for side in ("baseline", "candidate")
    }
    result = {
        "heads": heads,
        "sourceHashes": source_hashes,
        "nodeEnv": NODE_ENV,
        "bunVersion": bun_version,
        "phaseNotes": {
            "providersDialogIdle": (
                "includes ~1s of slash-command entry (prompt clear, "
                "/providers, Enter) before the 8s dialog pump; the dialog "
                "overlays the still-mounted home view, so no non-home "
                "timing claim is made from this phase"
            )
        },
        "dimensions": {"rows": ROWS, "cols": COLS},
        "resized": {"rows": RESIZED_ROWS, "cols": RESIZED_COLS},
        "sampleIntervalMs": SAMPLE_MS,
        "summary": summary,
        "inputContinuity": input_ok,
    }
    (out_dir / "petri-idle-summary.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
