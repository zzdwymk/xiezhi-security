"""Fetch pinned OCR test assets; validate before writing, never execute downloads."""
from pathlib import Path
import hashlib
import json
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'security-toolbox-server' / 'data' / 'models' / 'icp'
REV = '1cfba2e90fc938db55889873735088de210cc173'
ASSETS = [
    ('det.onnx', f'https://huggingface.co/SWHL/RapidOCR/resolve/{REV}/PP-OCRv3/ch_PP-OCRv3_det_infer.onnx', '3439588c030faea393a54515f51e983d8e155b19a2e8aba7891934c1cf0de526'),
    ('rec.onnx', f'https://huggingface.co/SWHL/RapidOCR/resolve/{REV}/PP-OCRv3/ch_PP-OCRv3_rec_infer.onnx', '897a3ededb38fee0dae2c1ccee38241f37df202c9509e3abca02e9217c5ee615'),
    ('ppocr_keys_v1.txt', 'https://raw.githubusercontent.com/PaddlePaddle/PaddleOCR/release/2.7/ppocr/utils/ppocr_keys_v1.txt', '28b2362ad4ab2dc38769aa72feb535e3a9ddb3fd2a7585a05920e6393b1dc7f7'),
]
DEST.mkdir(parents=True, exist_ok=True)
print(f'Model directory: {DEST}')
manifest = []
for name, url, expected in ASSETS:
    target = DEST / name
    if target.exists():
        data = target.read_bytes()
    else:
        with urllib.request.urlopen(url, timeout=120) as response:
            data = response.read(32 * 1024 * 1024 + 1)
    if len(data) > 32 * 1024 * 1024:
        raise RuntimeError(f'Asset exceeds download budget: {name}')
    digest = hashlib.sha256(data).hexdigest()
    if expected is not None and digest != expected:
        raise RuntimeError(f'Asset hash mismatch: {name}')
    if name == 'ppocr_keys_v1.txt':
        git_hash = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if git_hash != '84b885d8352226e49b1d5d791b8f43a663e246aa':
            raise RuntimeError('Dictionary revision mismatch')
    if not target.exists():
        target.write_bytes(data)
    manifest.append({'name': name, 'source': url, 'sha256': digest, 'bytes': len(data)})
    print(f'{name}: {len(data)} bytes, SHA256 {digest}')
print(json.dumps(manifest, ensure_ascii=False))
