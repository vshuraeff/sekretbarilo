---
title: What sekretbarilo is for
description: What the scanner is, why secrets in version control and in AI agent sessions are a risk, and the layers of defence it puts in their way.
section: explanation
---

## What is sekretbarilo?

**sekretbarilo** (Esperanto for "secret keeper") is a high-performance secret scanner designed for git workflows and AI coding agents. Written in Rust, it protects your codebase by:

- **Preventing secret leaks** in git commits through pre-commit hooks
- **Auditing repositories** for existing secrets in commit history
- **Protecting AI agent file reads** by blocking access to files containing secrets

Whether you're working solo or in a team, sekretbarilo acts as an automated guard against accidentally committing API keys, passwords, tokens, and other sensitive data.

## Why you need it

Secrets in version control are a critical security risk:

- Once committed, secrets remain in git history even if removed later
- Public repositories expose secrets to the entire internet
- AI coding agents may inadvertently leak secrets when accessing files
- Automated scanning catches what manual code review misses

sekretbarilo provides multiple layers of defense:

1. **Pre-commit scanning** blocks secrets before they enter your repository
2. **History auditing** finds secrets already in your git history
3. **Agent hooks** prevent AI tools from reading files with secrets

## Further reading

- [Getting Started]({{ '/getting-started/' | relative_url }}) to set up the pre-commit hook and watch it block a commit.
- [How secret detection works]({{ '/how-detection-works/' | relative_url }}) for how a value is recognised as a secret.
- [How the agent hooks work]({{ '/how-agent-hooks-work/' | relative_url }}) for the agent side of the protection.
