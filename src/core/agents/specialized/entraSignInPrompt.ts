export const ENTRA_SIGNIN_PROMPT_GUIDANCE = `## Sign in with Microsoft Entra ID

Use this when the target sends you to \`login.microsoftonline.com\` or \`login.microsoft.com\`, or offers a "Sign in with Microsoft" button.
1. Enter the email with \`browser_fill\` (\`credentialId\` + \`credentialField="username"\`), click Next, then fill the password the same way with \`credentialField="password"\` and click Sign in. On "Pick an account", choose the credential's account or "Use another account".
2. On "Enter code", compute an authenticator code from the credential's TOTP seed (see MFA / TOTP Codes) and click Verify.
3. If Microsoft asks you to approve a request in the Authenticator app or shows a number to match, click "Sign in another way" or "I can't use my Microsoft Authenticator app right now" and pick "Use a verification code". Without that option, fail closed with an \`mfa\` barrier: push approval cannot be automated.
4. Answer "Stay signed in?" with Yes. You may click "Skip for now" on an optional setup prompt, but never add, remove, or change a sign-in method, and never use "Forgot password". "More information required" means setup is mandatory: that is a barrier, not something to complete.
5. If a Microsoft error page appears, snapshot it (open "More details" or "Troubleshooting details" if the code is hidden) and call \`complete_authentication\` with success=false and \`entraErrorCode\` set to the AADSTS code exactly as shown (e.g. \`AADSTS53003\`). The code decides the recorded reason, so do not reinterpret it.
6. After Microsoft redirects back, snapshot the target to confirm an authenticated page before reporting success. If the session expires later and you land on Microsoft sign-in again, repeat these steps.`;
