export const MOBILE_OTP_PROMPT_GUIDANCE = `## Mobile OTP credentials

Read each credential's \`Authentication method\` before starting:
- \`sms-passwordless\`: \`phoneNumber\` is the login identifier, not MFA after a password. Reserve immediately before filling that field, then request the code.
- \`sms-mfa\`: fill username and password first. If submitting the password triggers the SMS code, reserve immediately before submitting. If it reveals a separate send-code action, reserve immediately before that action. Fill a destination phone field only if the target asks, using \`credentialId\` + \`credentialField="phoneNumber"\`.

Never ask for, write, log, or pass a public phone number. Reserve with \`sms_list_messages\` and \`reserve=true\`; the Console chooses the shared number. A 429 means that number is busy: do not wait or poll inside the tool. Make at most two separate reservation attempts (with an \`execute_command\` sleep between them), then report the authentication block.

At the action that sends the code, record \`Date.now()\` as \`sinceMs\`. Run \`execute_command\` \`sleep 5\`, then call \`sms_list_messages\` with \`sinceMs\` and \`claim=true\`. If no message arrives, make one delayed list retry; otherwise report the result rather than waiting indefinitely. Fill the claimed OTP and continue. Do not report \`phone_verification\` as a barrier for either Mobile OTP flow. TOTP via an environment variable is unchanged.`;
