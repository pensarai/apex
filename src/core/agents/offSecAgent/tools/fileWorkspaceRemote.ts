import type { ToolContext } from "./types";

interface Request {
  action: "resolve" | "read" | "write" | "delete" | "assert_absent";
  path: string;
  root?: string;
  content?: string;
  exclusive?: boolean;
  expectedHash?: string;
}

const PYTHON = String.raw`
import os, sys, json, base64, stat, hashlib, tempfile
LIMIT = 1048576
def read_text(p):
    fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ValueError('Not an ordinary file')
        data = f.read(LIMIT + 1)
    if len(data) > LIMIT: raise ValueError('Text mutation limit is 1048576 bytes')
    if b'\0' in data: raise ValueError('Binary file is not supported')
    data.decode('utf-8', errors='strict')
    return data
def canonical(p):
    cursor = p
    while not os.path.lexists(cursor):
        parent = os.path.dirname(cursor)
        if parent == cursor: break
        cursor = parent
    if os.path.lexists(cursor) and not os.path.exists(cursor):
        raise ValueError('Dangling symlink')
    return os.path.realpath(p)
def run(q):
    p = canonical(q['path'])
    root = q.get('root')
    if root and os.path.commonpath([canonical(root), p]) != canonical(root):
        raise ValueError('Path escapes file workspace')
    if q['action'] == 'resolve': return {'path': p}
    if q['action'] == 'assert_absent':
        if os.path.lexists(p): raise FileExistsError('File already exists: ' + p)
        return {}
    if q['action'] == 'read': return {'content': base64.b64encode(read_text(p)).decode('ascii')}
    def check():
        expected = q.get('expectedHash')
        if expected is not None and hashlib.sha256(read_text(p)).hexdigest() != expected:
            raise ValueError('File changed since it was read; re-read and prepare the change again')
    check()
    if q['action'] == 'delete':
        read_text(p)
        os.unlink(p)
        return {}
    data = base64.b64decode(q['content'], validate=True)
    if len(data) > LIMIT: raise ValueError('Text mutation limit is 1048576 bytes')
    if b'\0' in data: raise ValueError('Binary file is not supported')
    data.decode('utf-8', errors='strict')
    mode = None
    if os.path.lexists(p):
        if q.get('exclusive'): raise FileExistsError('File already exists: ' + p)
        info = os.lstat(p)
        if not stat.S_ISREG(info.st_mode): raise ValueError('Not an ordinary file')
        read_text(p)
        mode = stat.S_IMODE(info.st_mode)
    parent = os.path.dirname(p)
    os.makedirs(parent, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.apex-file-', dir=parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            if mode is None:
                mask = os.umask(0)
                os.umask(mask)
                mode = 0o666 & ~mask
            os.fchmod(f.fileno(), mode)
        check()
        if q.get('exclusive'):
            os.link(temporary, p)
        else:
            os.replace(temporary, p)
    finally:
        if os.path.lexists(temporary): os.unlink(temporary)
    return {}
try:
    payload = ''.join(os.environ['APEX_FILE_PAYLOAD_' + str(i)] for i in range(int(os.environ['APEX_FILE_PAYLOAD_COUNT'])))
    request = json.loads(base64.b64decode(payload))
    print(json.dumps({'ok': True, **run(request)}, ensure_ascii=True))
except Exception as e:
    print(json.dumps({'ok': False, 'error': str(e)[:2000]}))
`;

const POWERSHELL = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$utf8 = New-Object System.Text.UTF8Encoding($false, $true)
function Canonical([string]$p, [bool]$confined) {
  $full = [IO.Path]::GetFullPath($p)
  if ($full -match '^\\\\[?.]\\') { throw 'Windows device paths are not supported' }
  foreach ($part in $full.Substring([IO.Path]::GetPathRoot($full).Length).Split('\')) {
    if ($part -match '[. ]$|:' -or $part -match '^(con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:\.|$)') {
      throw 'Windows device names, alternate streams, and trailing dots/spaces are not supported'
    }
  }
  if ($confined) {
    $cursor = $full
    while ($cursor) {
      $item = Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue
      if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Reparse points are not supported in a confined file workspace'
      }
      $parent = [IO.Path]::GetDirectoryName($cursor)
      if ($parent -eq $cursor) { break }
      $cursor = $parent
    }
  }
  return $full
}
function ReadText([string]$p) {
  $item = Get-Item -LiteralPath $p -Force
  if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Not an ordinary file' }
  $stream = [IO.File]::Open($p, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    if ($stream.Length -gt 1048576) { throw 'Text mutation limit is 1048576 bytes' }
    $bytes = New-Object byte[] ([int]$stream.Length + 1)
    $count = 0
    while ($count -lt $bytes.Length) {
      $read = $stream.Read($bytes, $count, $bytes.Length - $count)
      if ($read -eq 0) { break }
      $count += $read
    }
    if ($count -eq $bytes.Length) { throw 'File grew during read; read it again' }
    $data = New-Object byte[] $count
    [Array]::Copy($bytes, $data, $count)
    if ($data -contains 0) { throw 'Binary file is not supported' }
    $null = $utf8.GetString($data)
    return ,$data
  } finally { $stream.Dispose() }
}
function CheckExpected($q, [string]$p) {
  if ($null -ne $q.expectedHash) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = [BitConverter]::ToString($sha.ComputeHash((ReadText $p))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    if ($hash -ne $q.expectedHash) { throw 'File changed since it was read; re-read and prepare the change again' }
  }
}
try {
  $payload = New-Object Text.StringBuilder
  for ($i = 0; $i -lt [int]$env:APEX_FILE_PAYLOAD_COUNT; $i++) {
    $null = $payload.Append([Environment]::GetEnvironmentVariable('APEX_FILE_PAYLOAD_' + $i))
  }
  $q = $utf8.GetString([Convert]::FromBase64String($payload.ToString())) | ConvertFrom-Json
  $p = Canonical $q.path ([bool]$q.root)
  if ($q.root) {
    $root = (Canonical $q.root $true).TrimEnd('\', '/')
    if (-not ($p.Equals($root, [StringComparison]::OrdinalIgnoreCase) -or $p.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase))) {
      throw 'Path escapes file workspace'
    }
  }
  $result = @{ok = $true}
  switch ($q.action) {
    'resolve' { $result.path = $p }
    'assert_absent' { if (Test-Path -LiteralPath $p) { throw ('File already exists: ' + $p) } }
    'read' { $result.content = [Convert]::ToBase64String((ReadText $p)) }
    'delete' {
      CheckExpected $q $p
      $null = ReadText $p
      [IO.File]::Delete($p)
    }
    'write' {
      if ($q.exclusive -and (Test-Path -LiteralPath $p)) { throw ('File already exists: ' + $p) }
      CheckExpected $q $p
      $bytes = [Convert]::FromBase64String($q.content)
      if ($bytes.Length -gt 1048576) { throw 'Text mutation limit is 1048576 bytes' }
      if ($bytes -contains 0) { throw 'Binary file is not supported' }
      $null = $utf8.GetString($bytes)
      if (Test-Path -LiteralPath $p) { $null = ReadText $p }
      $parent = [IO.Path]::GetDirectoryName($p)
      $null = [IO.Directory]::CreateDirectory($parent)
      $temporary = [IO.Path]::Combine($parent, '.apex-file-' + [Guid]::NewGuid().ToString('N'))
      try {
        [IO.File]::WriteAllBytes($temporary, $bytes)
        CheckExpected $q $p
        if ($q.exclusive -or -not [IO.File]::Exists($p)) { [IO.File]::Move($temporary, $p) }
        else { [IO.File]::Replace($temporary, $p, [NullString]::Value) }
      } finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
    }
    default { throw 'Unsupported file operation' }
  }
  $result | ConvertTo-Json -Compress
} catch { @{ok = $false; error = $_.Exception.Message} | ConvertTo-Json -Compress }
`;

export async function remoteFileOperation(
  ctx: ToolContext,
  request: Request,
): Promise<Record<string, unknown>> {
  const sandbox = ctx.sandbox;
  if (!sandbox) throw new Error("No sandbox configured for file operation");
  ctx.abortSignal?.throwIfAborted();
  const payload = Buffer.from(
    JSON.stringify({ ...request, root: request.root ?? ctx.fileWorkspaceRoot }),
  ).toString("base64");
  // cmd.exe drops environment values above 8191 characters.
  const chunks = payload.match(/.{1,6000}/g) ?? [];
  const envVars: Record<string, string> = {
    APEX_FILE_PAYLOAD_COUNT: String(chunks.length),
  };
  for (const [i, chunk] of chunks.entries())
    envVars[`APEX_FILE_PAYLOAD_${i}`] = chunk;
  if (sandbox.type === "windows")
    envVars.APEX_FILE_SCRIPT = Buffer.from(POWERSHELL, "utf8").toString(
      "base64",
    );
  const command =
    sandbox.type === "windows"
      ? `powershell.exe -NoProfile -NonInteractive -EncodedCommand ${Buffer.from(
          "& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:APEX_FILE_SCRIPT))))",
          "utf16le",
        ).toString("base64")}`
      : `python3 -c '${PYTHON.replaceAll("'", "'\\''")}'`;
  const result = await sandbox.execute(command, {
    envVars,
    timeout: 30,
    retries: 0,
  });
  if (!result.success || result.exitCode !== 0) {
    throw new Error(
      `Sandbox file operation failed: ${(result.stderr || result.stdout).slice(0, 2000)}`,
    );
  }
  if (result.stdout.length > 2 * 1024 * 1024)
    throw new Error("Sandbox file response exceeded the capture limit");
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    throw new Error(
      "Sandbox returned an invalid file response; no host fallback was attempted",
    );
  }
  if (parsed?.ok !== true)
    throw new Error(
      typeof parsed?.error === "string"
        ? parsed.error.slice(0, 2000)
        : "Sandbox file operation failed",
    );
  return parsed;
}
