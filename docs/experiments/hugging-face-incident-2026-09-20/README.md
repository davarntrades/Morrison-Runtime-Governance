# Hugging Face incident-study evidence deposit

Download [evidence-supplement.zip](evidence-supplement.zip) and unpack it to obtain all four original workflow archives, extracted raw records, hashes, provenance, new offline logs and the audit script. This deposit contains evidence and documentation only; no runtime code changes.

Verify the download against the ZIP digest in [SHA256SUMS.txt](SHA256SUMS.txt). Then, from the extracted directory, run:

```bash
sha256sum -c SHA256SUMS.txt
python evidence/audit_historical_artifacts.py
```

The original archive digest checks match GitHub metadata. Recomputing from raw action turns and target call records agrees with the published counts: 108 governed proposing trials, 108 refusals, zero governed destructive stub calls. The original Qwen success label is preserved in the raw record; the supplied audit identifies its corrected PARTIAL classification. No model calls were made for this recovery and audit.

The recovered original workflow archives expire on 20 October 2026 under their original 30-day retention. This commit-pinned copy makes access independent of that workflow retention. Use the exact Git commit URL for citation; a DOI-bearing archive is not claimed.

The extracted README describes source snapshots, dependencies, commands and evidence categories. The runtime source remains at f93c010e98530874787a3e3f6c8485343a62f94f for the fresh offline checks. The historical live records retain their individual source commits.
