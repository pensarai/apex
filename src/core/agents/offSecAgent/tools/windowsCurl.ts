export interface WindowsCurlOptions {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
  followRedirects: boolean;
  timeoutSeconds: number;
  maxBytes: number;
  exitMarker: string;
}

export interface WindowsCurlCommand {
  command: string;
  envVars: Record<string, string>;
}

/** Windows CRT argv quoting for ProcessStartInfo.Arguments (PS5.1 lacks ArgumentList). */
function quoteArg(s: string): string {
  if (!s) return '""';
  if (!/[\s"]/.test(s)) return s;
  let out = '"';
  let bs = 0;
  for (const ch of s) {
    if (ch === "\\") {
      bs++;
      continue;
    }
    if (ch === '"') {
      out += `${"\\".repeat(bs * 2 + 1)}"`;
      bs = 0;
    } else {
      out += "\\".repeat(bs) + ch;
      bs = 0;
    }
  }
  out += `${"\\".repeat(bs * 2)}"`;
  return out;
}

function buildCurlArgs(opts: WindowsCurlOptions): string {
  const argv = ["-s", "--show-error", "--no-buffer", "-i", "-X", opts.method];
  for (const [name, value] of Object.entries(opts.headers)) {
    argv.push("-H", `${name}: ${value}`);
  }
  if (opts.followRedirects) argv.push("-L");
  argv.push("--max-time", String(opts.timeoutSeconds), opts.url);
  return argv.map(quoteArg).join(" ");
}

// Each chunk stays under cmd.exe's 8191-char env var limit.
const BODY_CHUNK_CHARS = 6000;

// Fixed script body — request data arrives via env vars, so the encoded
// command length is constant regardless of body/headers size. Body chunks
// arrive as APEX_HTTP_BODY_0, _1, ... with APEX_HTTP_BODY_COUNT and
// APEX_HTTP_BODY_LENGTH (total encoded chars) for reconstruction + validation.
const SCRIPT = [
  "$ErrorActionPreference='Stop'",
  "$curlArgs=[Environment]::GetEnvironmentVariable('APEX_HTTP_CURL_ARGS')",
  "$mark=[Environment]::GetEnvironmentVariable('APEX_HTTP_MARKER')",
  "$maxB=[int][Environment]::GetEnvironmentVariable('APEX_HTTP_MAX_BYTES')",
  "$budgetMs=[int][Environment]::GetEnvironmentVariable('APEX_HTTP_BUDGET_MS')",
  "$bodyCount=[int][Environment]::GetEnvironmentVariable('APEX_HTTP_BODY_COUNT')",
  "$bodyLen=[int][Environment]::GetEnvironmentVariable('APEX_HTTP_BODY_LENGTH')",
  "if(-not $curlArgs -or -not $mark){throw 'missing APEX_HTTP env vars'}",
  // Reconstruct the body from chunks, validating BEFORE any HTTP is sent.
  "$body=''",
  "if($bodyCount -gt 0){",
  "$sb=New-Object Text.StringBuilder",
  "for($i=0;$i -lt $bodyCount;$i++){",
  '$chunk=[Environment]::GetEnvironmentVariable("APEX_HTTP_BODY_$i")',
  'if($null -eq $chunk){throw "missing body chunk $i"}',
  "[void]$sb.Append($chunk)",
  "}",
  "$body=$sb.ToString()",
  "}",
  // Length guard runs for count 0 too: an inconsistent count0/positive-length
  // env is rejected, not silently treated as no-body.
  'if($body.Length -ne $bodyLen){throw "body chunk length mismatch: $($body.Length) vs $($bodyLen)"}',
  "$tf=$null",
  "$p=$null",
  "try{",
  "if($body){$tf=[IO.Path]::GetTempFileName();[IO.File]::WriteAllBytes($tf,[Convert]::FromBase64String($body));$curlArgs+=' --data-binary \"@'+$tf+'\"'}",
  "$pi=New-Object Diagnostics.ProcessStartInfo",
  "$pi.FileName='curl.exe'",
  "$pi.Arguments=$curlArgs",
  "$pi.UseShellExecute=$false",
  "$pi.RedirectStandardOutput=$true",
  "$sw=[Diagnostics.Stopwatch]::StartNew()",
  "$p=[Diagnostics.Process]::Start($pi)",
  "$is=$p.StandardOutput.BaseStream",
  "$os=[Console]::OpenStandardOutput()",
  "$buf=New-Object byte[] 65536",
  "$tot=[int64]0",
  "$ov=$false",
  "$eof=$false",
  "while($true){",
  "$remain=[int]($budgetMs-$sw.ElapsedMilliseconds)",
  "if($remain -le 0){break}",
  // Read min(buffer, remaining+1): one byte past the cap proves overflow.
  "$toRead=[int]([Math]::Min(65536,$maxB-$tot+1))",
  "if($toRead -le 0){$ov=$true;break}",
  "$t=$is.ReadAsync($buf,0,$toRead)",
  "if(-not $t.Wait($remain)){break}",
  "$n=$t.Result",
  "if($n -eq 0){$eof=$true;break}",
  "$emit=[int]([Math]::Min($n,$maxB-$tot))",
  // Stream each chunk as read so timeout/error preserves partial evidence.
  "if($emit -gt 0){$os.Write($buf,0,$emit)}",
  "$tot+=$n",
  "if($tot -gt $maxB){$ov=$true;break}",
  "}",
  // Overflow: no marker — the parser labels marker-less output as byte-cap.
  "if($ov){exit 0}",
  // Natural end: curl closed stdout, so the transfer is done (a 200 or curl's
  // own --max-time exit 28). Wait for exit on a fixed grace — not the leftover
  // request budget, which a deadline-hugging transfer exhausts — so the marker
  // is emitted and the parser reads a truthful curl-exit/end, not sandbox-exec.
  // A non-EOF break means the wrapper budget ran out mid-read (curl still
  // running); exit without a marker so that stays a sandbox timeout.
  "if(-not $eof){exit 1}",
  "if(-not $p.WaitForExit(5000)){exit 1}",
  '$eb=[Text.Encoding]::UTF8.GetBytes("`n$mark$($p.ExitCode)`n")',
  "$os.Write($eb,0,$eb.Length)",
  "exit 0",
  "}finally{",
  // Process cleanup: kill if running (catch only if it exited in the race),
  // require bounded WaitForExit, always Dispose via inner finally.
  "try{",
  "if($p){",
  "try{",
  "if(-not $p.HasExited){",
  "try{$p.Kill()}catch{if(-not $p.HasExited){throw}}",
  "}",
  "if(-not $p.HasExited){",
  "if(-not $p.WaitForExit(5000)){throw 'curl cleanup unconfirmed'}",
  "}",
  "}finally{",
  "$p.Dispose()",
  "}",
  "}",
  // Temp file always deleted, even if process cleanup above threw.
  "}finally{",
  "if($tf){[IO.File]::Delete($tf)}",
  "}",
  "}",
].join("\n");

const ENCODED = Buffer.from(SCRIPT, "utf16le").toString("base64");

/**
 * Builds a Windows sandbox curl wrapper. The powershell.exe command is a
 * fixed-length encoded script; request data (CRT-quoted argv, base64 body
 * chunks, marker, config) travels in the returned envVars. The caller must
 * pass envVars through to sandbox.execute.
 */
export function buildWindowsCurlCommand(
  opts: WindowsCurlOptions,
): WindowsCurlCommand {
  const bodyB64 =
    opts.body !== undefined
      ? Buffer.from(opts.body, "utf8").toString("base64")
      : "";
  const envVars: Record<string, string> = {
    APEX_HTTP_CURL_ARGS: buildCurlArgs(opts),
    APEX_HTTP_MARKER: opts.exitMarker,
    APEX_HTTP_MAX_BYTES: String(opts.maxBytes),
    APEX_HTTP_BUDGET_MS: String(opts.timeoutSeconds * 1000),
    APEX_HTTP_BODY_COUNT: "0",
    APEX_HTTP_BODY_LENGTH: "0",
  };
  // Chunk the base64 body so each env var stays under cmd.exe's 8191-char
  // limit. Count/length are always set — count 0 ignores ambient chunks.
  for (let i = 0; i < bodyB64.length; i += BODY_CHUNK_CHARS) {
    const idx = i / BODY_CHUNK_CHARS;
    envVars[`APEX_HTTP_BODY_${idx}`] = bodyB64.substring(
      i,
      i + BODY_CHUNK_CHARS,
    );
  }
  if (bodyB64.length > 0) {
    envVars.APEX_HTTP_BODY_COUNT = String(
      Math.ceil(bodyB64.length / BODY_CHUNK_CHARS),
    );
    envVars.APEX_HTTP_BODY_LENGTH = String(bodyB64.length);
  }
  return {
    command: `powershell.exe -NoProfile -NonInteractive -EncodedCommand ${ENCODED}`,
    envVars,
  };
}
