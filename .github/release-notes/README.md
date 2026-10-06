# Release notes

`v<version>.md` in this directory is the body of the GitHub release for tag `v<version>`. `release.yml` publishes the file unchanged. Its first job fails before anything is built when the file for the pushed tag is missing, empty or starts with a version heading.

Releases are squash commits, so a generated changelog would be the commit subject alone. The notes are written by hand and reviewed with the release commit.

## Format

Start with the content. The release title already carries the version, so do not repeat it as a heading. Use the sections that apply:

- `## Highlights`: the changes a user notices, one bold lead sentence each.
- `## Upgrade notes`: anything a user has to do or that changes existing behavior. End with the upgrade command:

  ```text
  Upgrade: `brew upgrade vshuraeff/tap/sekretbarilo`, then `sekretbarilo doctor`.
  ```

- `## Changes`: grouped by area under `###` headings, one fact per bullet.

Name commands, rules and settings in code spans exactly as they are spelled (`redact-claude`, not "Redact-claude"). Keep the notes free of local paths, host names and private project names.

## Releasing

1. Write `v<version>.md` and commit it together with the version bump. CI runs on that push to `master`.
2. Preview the rendering before tagging. Render the file through GitHub's markdown API with `gh api markdown -f mode=gfm -f text="$(cat .github/release-notes/v<version>.md)"`, or read it on the branch page.
3. Push the tag `v<version>` on that commit after CI is green. The release job publishes the notes, the tarballs and the `.deb` packages.
4. To correct published notes, edit the file on `master` and apply it with `gh release edit v<version> --notes-file .github/release-notes/v<version>.md`, so the file and the release page stay the same.
