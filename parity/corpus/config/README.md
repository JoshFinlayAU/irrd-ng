# irrd.yaml parity corpus

Each `*.yaml` here is a small, synthetic `irrd.yaml` aimed at one branch of IRRd v4's configuration loading and checking (`_staging_reload_check` and `_check_staging_config`), and `expected.jsonl` is v4 4.5.4's verdict on every one of them: its error list and its startup message. `crash/` holds files that make v4 raise instead of reporting an error, with `crash/expected.jsonl` recording the exception, and `yaml/` holds fuzzed YAML documents (one per distinct outcome) with what PyYAML's `safe_load` made of them. `crates/config/tests/parity_corpus.rs` checks irrd-ng against all three; only DIV-001 and DIV-002 (`docs/divergences.md`) may differ. Paths in the files must exist, or not exist, identically on the host and in the v4 container (`/tmp`, `/etc`, `/nonexistent-irrd-ng`). After adding or changing a file, regenerate the expectations from the repository root with the pinned v4 image (`parity/up.sh` builds it) and commit them:

```sh
parity/oracle/run.sh config parity/corpus/config > parity/corpus/config/expected.jsonl
docker run --rm --network none --entrypoint python \
  -v "$PWD/parity/corpus/config/crash:/input:ro" -v "$PWD/parity/v4/irrd.yaml:/etc/irrd/irrd.yaml:ro" \
  irrd-ng-parity/irrd-v4:4.5.4 /input/oracle.py /input 2>/dev/null > parity/corpus/config/crash/expected.jsonl
docker run --rm --network none --entrypoint python -v "$PWD/parity/corpus/config/yaml:/input:ro" \
  irrd-ng-parity/irrd-v4:4.5.4 /input/oracle.py /input > parity/corpus/config/yaml/expected.jsonl
```
