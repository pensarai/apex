/** CRT quoting for ProcessStartInfo.Arguments; cmd.exe never sees these values. */
function quoteArg(value: string): string {
  if (!value) return '""';
  if (!/[\s"]/.test(value)) return value;
  return `"${value.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, "$1$1")}"`;
}

const script = [
  "$ErrorActionPreference='Stop'",
  "$pi=[Diagnostics.ProcessStartInfo]::new()",
  "$pi.FileName=[Environment]::GetEnvironmentVariable('APEX_PROGRAM_FILE')",
  "$count=[int][Environment]::GetEnvironmentVariable('APEX_PROGRAM_ARG_COUNT')",
  "$argsText=''",
  "for($i=0;$i -lt $count;$i++){$chunk=[Environment]::GetEnvironmentVariable('APEX_PROGRAM_ARGS_'+$i);if($null -eq $chunk){throw 'Missing program arguments'};$argsText+=$chunk}",
  "$pi.Arguments=$argsText",
  "$pi.UseShellExecute=$false",
  "$p=[Diagnostics.Process]::Start($pi)",
  "$p.WaitForExit()",
  "exit $p.ExitCode",
].join(";");
const command = `powershell.exe -NoProfile -NonInteractive -EncodedCommand ${Buffer.from(script, "utf16le").toString("base64")}`;

export function windowsProgramInvocation(executable: string, args: string[]) {
  const text = args.map(quoteArg).join(" ");
  const envVars: Record<string, string> = {
    APEX_PROGRAM_FILE: executable,
    APEX_PROGRAM_ARG_COUNT: String(Math.ceil(text.length / 6000)),
  };
  for (let offset = 0; offset < text.length; offset += 6000) {
    envVars[`APEX_PROGRAM_ARGS_${offset / 6000}`] = text.slice(
      offset,
      offset + 6000,
    );
  }
  return { command, envVars };
}
