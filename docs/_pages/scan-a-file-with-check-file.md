---
title: Scan a single file with check-file
description: Run the agent hook's file check by hand — on a path, on a simulated hook payload, across a CI job, or before opening a file in an editor.
section: how-to
---

The `check-file` command can be used standalone, outside of the Claude Code hook context. This is useful for testing, CI pipelines, or integrating with other tools.

## Scan a File by Path

```sh
sekretbarilo check-file src/config.rs
```

Exit code 0 = clean, exit code 2 = secrets found.

## Read File Path from Stdin JSON (Agent Hook Mode)

Simulate the Claude Code hook payload:

```sh
echo '{"tool_input":{"file_path":"src/config.rs"}}' | sekretbarilo check-file --stdin-json
```

This is the same mode used by the agent hook.

## Example: CI Pipeline

Run `check-file` on all source files in CI:

```sh
#!/bin/sh
# scan all python files for secrets

for file in $(find src -name '*.py'); do
  sekretbarilo check-file "$file"
  if [ $? -eq 2 ]; then
    echo "secret detected in $file"
    exit 1
  fi
done

echo "all files clean"
```

## Example: Pre-Read Script

Use `check-file` in a script before opening files in an editor:

```sh
#!/bin/sh
# check file before opening in vim

sekretbarilo check-file "$1"
if [ $? -eq 2 ]; then
  echo "file contains secrets. open anyway? (y/n)"
  read -r answer
  if [ "$answer" != "y" ]; then
    exit 1
  fi
fi

vim "$1"
```

## Related pages

- [Stdin JSON Payload]({{ '/agent-hooks/#stdin-json-payload' | relative_url }}) for every field the hook payload accepts.
- [Output Format]({{ '/agent-hooks/#output-format' | relative_url }}) for what `check-file` prints and when it exits 2.
- [CLI reference]({{ '/cli-reference/' | relative_url }}) for the full command syntax.
