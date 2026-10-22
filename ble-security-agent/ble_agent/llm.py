"""LLM-assisted analysis via the Claude API (optional; needs ANTHROPIC_API_KEY)."""
import json
import os

DEFAULT_MODEL = os.getenv("BLE_AGENT_MODEL", "claude-sonnet-5-5")

SYSTEM = (
    "You are a defensive IoT security analyst. Given BLE scan results and rule-based findings, "
    "write a concise Markdown report: 1) executive summary, 2) per-device risk rating with reasoning, "
    "3) prioritised remediation advice for the device owner. Do not provide exploitation steps."
)


def analyze(devices: list[dict], findings: list[dict], model: str = DEFAULT_MODEL, lang: str = "zh") -> str:
    import anthropic

    client = anthropic.Anthropic()
    payload = json.dumps({"devices": devices, "findings": findings}, ensure_ascii=False)
    msg = client.messages.create(
        model=model,
        max_tokens=4000,
        system=SYSTEM + (" Answer in Simplified Chinese." if lang == "zh" else ""),
        messages=[{"role": "user", "content": payload}],
    )
    return "".join(b.text for b in msg.content if b.type == "text")
