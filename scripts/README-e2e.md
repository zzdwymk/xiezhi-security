# Real-runtime release regression

Full regression explicitly enables the six Java → Python runtime contract tests. Local OCR was removed; no OCR models or OCR test prerequisites remain.

Use an existing Python environment with the versions in `ai-runtime/requirements.txt`. The unused top-level `langchain` package is not required. The runner accepts `-Python` and does not install packages or change global Windows settings.

```powershell
# Six Python-runtime contract cases only
pwsh -File scripts/run-ai-runtime-e2e.ps1
# Complete Maven suite with these cases enabled
pwsh -File scripts/run-ai-runtime-e2e.ps1 -FullRegression
```

The runner uses loopback ports 18091/18092, rejects occupied ports, generates ephemeral secrets, isolates runtime data under `reports`, and stops its own processes in `finally`. It does not modify live desktop credentials.

The six contract cases use the repository's deterministic LLM fixture, while Python app/LangGraph/RAG/HTTP/Java harness execute for real. Task execution mocks prevent accidental scans. This is not full real-model-provider inference; separately verify the authorized `127.0.0.1:3425` relay.

ICP lookup retains the official browser-assisted/manual flow and captured-results import. No local automatic OCR solver is provided.
