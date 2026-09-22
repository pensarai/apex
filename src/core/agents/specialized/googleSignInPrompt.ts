import type { BrowserEngine } from "../offSecAgent/tools/playwrightMcp";

export type { BrowserEngine };

export const GOOGLE_SIGNIN_PROMPT_GUIDANCE = `## Sign in with Google

When a credential is marked Sign-in: Google:
1. Open the credential's Login URL on the target. Click the target's Google / Sign in with Google button. Do NOT fill the target's native username or password form.
2. On accounts.google.com, snapshot, then \`browser_fill\` the identifier (email) with \`credentialId\` + \`credentialField="username"\`. Continue, then fill the password with \`credentialId\` + \`credentialField="password"\`. Never type a password or employee ID into the prompt or into \`execute_command\`.
3. If Google asks to verify the account, fill **Google employee ID** with \`credentialId\` + \`credentialField="Google employee ID"\` (the name is in Additional secret fields).
4. Fail closed: if Google shows "this browser or app may not be secure", a CAPTCHA, or a blocked-app interstitial, call \`complete_authentication\` with success=false and name the barrier. Do not try account recovery, password reset, or a different browser profile.
5. After Google returns to the target, snapshot to confirm the session, then \`complete_authentication\` as usual.`;

export function browserEngineForGoogleSignIn(
  hasGoogleSignIn: boolean,
): BrowserEngine {
  return hasGoogleSignIn ? "chrome" : "camoufox";
}
