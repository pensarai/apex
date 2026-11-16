import type { OperatorSnapshot } from "../operator/contract";

export function needsSessionInput(snapshot: OperatorSnapshot): boolean {
  return !!(
    snapshot.approvals.length ||
    snapshot.questions?.questions.length ||
    snapshot.reviewPlan
  );
}

export function latestSessionReply(snapshot: OperatorSnapshot): string {
  for (let index = snapshot.messages.length - 1; index >= 0; index--) {
    const message = snapshot.messages[index];
    if (message.role === "assistant" && message.content.trim())
      return `${index}:${message.createdAt}:${message.content.length}`;
  }
  return "";
}

export function sessionUnread(
  previousReply: string,
  nextReply: string,
  unread: boolean,
  viewing: boolean,
): boolean {
  if (viewing) return false;
  return unread || (!!nextReply && previousReply !== nextReply);
}
