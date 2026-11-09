import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@pensarai/design-system/ui/dialog";
import { Input } from "@pensarai/design-system/ui/input";
import { useEffect, useState } from "react";
import type { SkillRow } from "../shared";
import { api } from "./bridge";

export default function Skills({
  close,
  initialSlug,
}: {
  close: () => void;
  initialSlug?: string;
}) {
  const [skills, setSkills] = useState<SkillRow[]>([]);
  const [query, setQuery] = useState("");
  const [selected, select] = useState(initialSlug);
  const [content, setContent] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    let current = true;
    api
      .skills()
      .then((items) => {
        if (current) setSkills(items);
      })
      .catch((e) => {
        if (current) setError(String(e));
      });
    return () => {
      current = false;
    };
  }, []);
  const matches = skills.filter((s) =>
    [s.name, s.slug, s.description]
      .join(" ")
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  const skill = matches.find((s) => s.slug === selected) ?? matches[0];
  const slug = skill?.slug;
  useEffect(() => {
    let active = true;
    setContent("");
    if (slug)
      api
        .skillContent({ slug })
        .then((text) => {
          if (active) setContent(text);
        })
        .catch((e) => {
          if (active) setContent(String(e));
        });
    return () => {
      active = false;
    };
  }, [slug]);
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) close();
      }}
    >
      <DialogContent className="skill-dialog">
        <DialogHeader>
          <DialogTitle>Skills</DialogTitle>
          <DialogDescription>
            Built-in, project and user skills available in this directory.
          </DialogDescription>
        </DialogHeader>
        <Input
          autoFocus
          placeholder="Find a skill"
          aria-label="Find a skill"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        {error && <p role="alert">{error}</p>}
        <div className="split">
          <div className="library">
            {matches.map((s) => (
              <button
                key={s.slug}
                className="record"
                aria-pressed={s.slug === slug}
                type="button"
                onClick={() => select(s.slug)}
              >
                <strong>{s.name}</strong>
                <span>{s.source}</span>
              </button>
            ))}
            {!matches.length && <p className="empty">No matching skills.</p>}
          </div>
          {skill && (
            <section className="detail inspector">
              <h2>{skill.name}</h2>
              <p>{skill.description}</p>
              {!!skill.scripts.length && (
                <p>Scripts · {skill.scripts.join(", ")}</p>
              )}
              <h3>Instructions</h3>
              <pre>{content}</pre>
            </section>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
