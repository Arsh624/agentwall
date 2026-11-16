# Prompts

## 1. Fable 5.2 (paste as the first message)

```
Build agentwall. Read docs/SPEC.md, docs/PLAN.md and docs/PROGRESS.md first.

How to work:
- First run git init, then commit the docs.
- Run docs/PLAN.md milestone by milestone, in order, with superpowers:subagent-driven-development.
  Write tests first (superpowers:test-driven-development) and run superpowers:verification-before-completion before you mark a task done.
- Be frugal. Each task has a model tag:
  [FABLE] = do it yourself (M1 proxy, M3 flow control, M5 credential broker, M8 integration).
  [SONNET] = send it to a subagent with model "sonnet".
  [HAIKU] = send it to a subagent with model "haiku".
  You review every subagent's work before you accept it.
- Use the simplest implementation that works: the Go standard library first, and only the dependencies listed in SPEC §5. No extra features.
- After EVERY task: update docs/PROGRESS.md (status, next task, decisions, known issues), then git commit.
  That file is the handoff if this session runs out of limit. Keep it current.
- Don't stop to ask me about small choices. Pick the option the spec implies and write it down under "Decisions made".
- Ask me only for things you can't do yourself (signing in, GitHub repo creation, secrets).
- If you get low on limit, finish the current task, update PROGRESS.md, commit, and stop.

Start with M0.
```

## 2. Backup (Opus 5.5 / Sonnet 5.5, new chat in the same folder)

```
Continue building agentwall. Read docs/PROGRESS.md, docs/PLAN.md, docs/SPEC.md and git log --oneline -20.
Check that the last task in PROGRESS.md actually passes (go test ./...). Fix it if not.
Then continue from "Next task" with superpowers:subagent-driven-development.
Same rules as before: do the [FABLE]-tagged tasks yourself, send the [SONNET] and [HAIKU] ones to subagents with those models,
write tests first, keep it basic, and update PROGRESS.md and commit after every task.
```
