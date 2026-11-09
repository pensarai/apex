import { Button } from "@pensarai/design-system/ui/button";
import { Input } from "@pensarai/design-system/ui/input";
import { useState } from "react";
import type { OperatorAction, Question } from "./contract";

export function Questions({
  questions,
  id,
  submit,
  disabled,
}: {
  questions: Question[];
  id: string;
  submit: (action: OperatorAction) => void;
  disabled: boolean;
}) {
  const [answers, setAnswers] = useState<Record<string, string[]>>({});
  const [text, setText] = useState<Record<string, string>>({});
  return (
    <form
      className="op-review"
      onSubmit={(e) => {
        e.preventDefault();
        submit({
          type: "answer",
          toolCallId: id,
          skip: false,
          answers: questions.map((q) => ({
            questionId: q.id,
            selectedOptionIds: answers[q.id] ?? [],
            freeformText: text[q.id]?.trim() || null,
          })),
        });
      }}
    >
      <fieldset disabled={disabled}>
        {questions.map((q) => (
          <div key={q.id}>
            <h3>{q.header}</h3>
            <p>{q.question}</p>
            {q.options.map((o) => (
              <label key={o.id} className="op-check" title={o.description}>
                <input
                  type={q.multiSelect ? "checkbox" : "radio"}
                  name={q.id}
                  checked={answers[q.id]?.includes(o.id) ?? false}
                  onChange={(e) => {
                    const checked = e.target.checked;
                    setAnswers((prev) => ({
                      ...prev,
                      [q.id]: q.multiSelect
                        ? checked
                          ? [...(prev[q.id] ?? []), o.id]
                          : (prev[q.id] ?? []).filter((v) => v !== o.id)
                        : [o.id],
                    }));
                  }}
                />
                {o.label}
              </label>
            ))}
            {q.allowFreeform !== false && (
              <Input
                aria-label={`Other answer to ${q.header}`}
                placeholder="Other answer"
                value={text[q.id] ?? ""}
                onChange={(e) => setText({ ...text, [q.id]: e.target.value })}
              />
            )}
          </div>
        ))}
        <div className="actions">
          <Button
            type="submit"
            variant="constructive"
            disabled={questions.some(
              (q) => !answers[q.id]?.length && !text[q.id]?.trim(),
            )}
          >
            Submit answers
          </Button>
          <Button
            type="button"
            onClick={() =>
              submit({
                type: "answer",
                toolCallId: id,
                skip: true,
                answers: [],
              })
            }
          >
            Skip questions
          </Button>
        </div>
      </fieldset>
    </form>
  );
}
