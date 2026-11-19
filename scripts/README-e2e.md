# Real-runtime and OCR release regression

The ordinary `mvn test` run remains suitable for development without external runtime/model assets. A release/full-regression claim must use the gate below, which explicitly enables the six Python-runtime contract tests and requires the three real OCR assets. Missing/invalid configured OCR assets fail; they must not be reported as a passing release.

## Prepare

Use Python with the versions in `ai-runtime/requirements.txt`. The unused top-level `langchain` package is not required. The script accepts `-Python` to select an existing isolated Python environment; it does not install packages or alter Windows/global environment settings.

```powershell
python scripts/fetch-ocr-e2e-models.py
```

This downloads pinned PP-OCRv3 ONNX detector/recognizer and the official character dictionary, verifies hashes before writing, and refuses mismatching existing assets. Models remain in the ignored backend data directory, not in Git. The two ONNX models use the fixed [SWHL/RapidOCR revision](https://huggingface.co/SWHL/RapidOCR/tree/1cfba2e90fc938db55889873735088de210cc173/PP-OCRv3); the dictionary is verified against both SHA-256 and the upstream Git blob hash.

| File | SHA-256 |
|---|---|
| det.onnx | 3439588c030faea393a54515f51e983d8e155b19a2e8aba7891934c1cf0de526 |
| rec.onnx | 897a3ededb38fee0dae2c1ccee38241f37df202c9509e3abca02e9217c5ee615 |
| ppocr_keys_v1.txt | 28b2362ad4ab2dc38769aa72feb535e3a9ddb3fd2a7585a05920e6393b1dc7f7 |

## Run

```powershell
# Six existing Java → real Python runtime contract tests only
pwsh -File scripts/run-ai-runtime-e2e.ps1
# Whole Maven suite, including the six runtime cases and real OCR inference
pwsh -File scripts/run-ai-runtime-e2e.ps1 -FullRegression
# Alternative model directory
pwsh -File scripts/run-ai-runtime-e2e.ps1 -FullRegression -OcrModels C:\path\to\verified-models
```

The runner uses loopback ports 18091/18092, rejects occupied ports, generates ephemeral runtime/signing secrets, isolates runtime data under `reports`, and stops only its own processes in `finally`. It does not reuse/change the live desktop runtime token or settings. Evidence is recorded in the printed directory. A populated model directory is not a substitute for the inference assertions.

## Test boundaries

The six existing contract cases use the repository's **deterministic LLM fixture server**, while the Python app, LangGraph/RAG, HTTP protocol and Java harness execute for real. Task execution is mocked by the existing route tests to prevent accidental scanning. This is not end-to-end real model-provider inference; a separate real `127.0.0.1:3425` validation is still required by the project acceptance criteria.

OCR runs the actual pinned ONNX models, validates printed `TEST`, matching and in-image coordinates. This is a synthetic inference oracle, not a claim of calibrated accuracy on all real-world challenge images. Production OCR still needs `ICP_OCR_MODELS` / `toolbox.recon.icp-ocr-models-path`; these model binaries are not silently embedded in the desktop package.
