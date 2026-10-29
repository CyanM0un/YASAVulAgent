# prepare

`prepare` is the deterministic boundary of discover: it does not call a model, the network, or live YASA. It passes available init resources, repository files, and the recovery ledger to `screen`.

- Git repositories use tracked files plus unignored untracked files; non-Git directories use a filesystem walk.
- VCS data, dependencies, caches, and runtime outputs are recorded as exclusions; tests, examples, and documentation are retained and marked as reference material.
- Text files receive a streaming SHA-256 fingerprint; large text files are only marked `large`; binary files record only their size and type.
- Recovery preserves completed files, tasks, entries, and evidence; interrupted `running` tasks are reset to `pending`.
- This version assumes that source code is unchanged during recovery and does not implement source-change detection or invalidation propagation.

Artifacts are written to `init-resources.json`, `files.json`, `excluded-files.json`, and `prepare.json` under `stages/discover/`.
