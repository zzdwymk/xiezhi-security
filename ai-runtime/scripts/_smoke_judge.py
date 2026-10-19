import json
import sys

sys.path.insert(0, ".")
from app.semantic_judge import baseline_for, circuit_breaker, max_risk, parse_verdict

print("baseline dir_scan:", baseline_for("dir_scan"))
print("baseline sqlmap:", baseline_for("sqlmap_scan"))
print("baseline unknown:", baseline_for("rm_thing"))
print("max_risk:", max_risk("SAFE", "CRITICAL"), max_risk("LOW", "CAUTION"))
print("breaker:", circuit_breaker("judge_timeout").to_dict())

payload = {
    "allow": True,
    "behaviour": "SQL注入探测",
    "risk": "HIGH",
    "confidence": 0.9,
    "summary": "注入测试",
}
v = parse_verdict(json.dumps(payload, ensure_ascii=False))
print("parsed allow (should be False because HIGH):", v.allow, v.risk, v.behaviour)

good = {
    "allow": True,
    "behaviour": "常规安全探测",
    "risk": "SAFE",
    "confidence": 0.95,
    "summary": "仅读取响应头",
}
v2 = parse_verdict("```json\n" + json.dumps(good, ensure_ascii=False) + "\n```")
print("fenced parse:", v2.allow, v2.behaviour, v2.confidence)

for bad in ('not json', '{"allow":true}', '{"allow":"yes","behaviour":"常规安全探测","risk":"SAFE","confidence":0.9,"summary":"x"}'):
    try:
        parse_verdict(bad)
        print("UNEXPECTED ACCEPT:", bad)
    except Exception as error:
        print("rejected as expected:", type(error).__name__)
