import os
import re
import requests

#  MODEL CONFIG
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "llama3:latest")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")

def _ollama_generate(prompt: str, model: str = DEFAULT_MODEL, timeout_sec: int = None ) -> str:
    """
    Fast Ollama runner via HTTP API (keeps model warm).
    """
    try:
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            # keep model loaded so next calls are faster
            "keep_alive": "10m",
            "options": {
                "temperature": 0.1,
                "num_predict": 512,  
                "num_ctx": 4096,      
                "num_thread": 12
            }
        }
        
        r = requests.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=300)
        
        if r.status_code != 200:
            return f"⚠️ Ollama HTTP {r.status_code}: {r.text}"
            
        data = r.json()
        out = (data.get("response") or "").strip()
        return out if out else "⚠️ Empty response."
        
    except requests.Timeout:
        return "⚠️ AI response timeout (model took too long)."
    except Exception as e:
        return f"❌ Ollama error: {e}"


        


#  IP EXPLAIN (agent.py uses this)
def mistral_explain(ip: str, summary: dict | None = None) -> str:
    prompt = f"""
You are a SOC analyst.
Rules: Use ONLY provided facts. If unknown, say Unknown and list safe checks.

IP: {ip}

Return 4 bullets:
- Meaning
- 2 generic causes
- 3 safe checks
- Escalation note
""".strip()
    return _ollama_generate(prompt)


#  BULLET NORMALIZER (FORCE 5 BULLETS + LINE-BY-LINE)
def _normalize_5_bullets(raw: str, iface: str, device_hint: str) -> str:
    raw = (raw or "").strip()

    # 1) If model mashed everything in one line, split by "•"
    if "•" in raw:
        parts = [p.strip() for p in raw.split("•") if p.strip()]
        lines = [f"• {p}" for p in parts]
    else:
        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]

    # 2) Keep only bullets; also convert "- " to bullet
    bullets = []
    for ln in lines:
        if ln.startswith("•"):
            bullets.append(ln.strip())
        elif ln.startswith("- "):
            bullets.append(("• " + ln[2:].strip()).strip())

    # Helper: detect empty bullets like "• SAFE show commands:"
    def _is_empty_bullet(b: str) -> bool:
        b_low = b.lower().strip()
        empty_headers = [
            "• top 2 likely causes:",
            "• safe show commands:",
            "• evidence to collect:",
            "• escalation note:",
            "• meaning:",
        ]
        return (b_low in empty_headers) or (b_low.endswith(":") and len(b_low) <= 30)

    iface_missing = (not iface) or (iface.strip().upper() == "N/A")

    # 3) Build safe command list (no guessing; interface exact if present)
    if not iface_missing:
        if device_hint == "huawei":
            cmds = [
                f"display interface {iface}",
                f"display interface brief | include {iface}",
                f"display logbuffer | include {iface}",
            ]
        elif device_hint == "asa":
            cmds = [
                f"show interface {iface}",
                f"show interface {iface} | include line|protocol|error|drop",
                f"show logging | include {iface}",
            ]
        else:
            # IOS-safe baseline; interface status is switch-only but safe as optional
            cmds = [
                f"show interface {iface}",
                f"show logging | include {iface}",
                f"show interface status | include {iface}",
            ]
    else:
        if device_hint == "huawei":
            cmds = [
                "display interface brief",
                "display logbuffer | include LINK|down|UP|Error",
                "display logbuffer | include interface",
            ]
        elif device_hint == "asa":
            cmds = [
                "show interface ip brief",
                "show logging | include LINK|down|up|error",
                "show logging | include interface",
            ]
        else:
            cmds = [
                "show ip interface brief",
                "show logging | include LINK|down|UP|ERR|disable",
                "show logging | include interface",
            ]

    cmd_block = " ; ".join([f"`{c}`" for c in cmds[:3]])

    # 4) Safe defaults (no hallucination)
    meaning = f"Interface {iface} is link down." if not iface_missing else "Link down reported (interface not parsed)."
    causes = "(1) physical disconnection/cable/transceiver, (2) remote device down/powered off"
    evidence = "Collect interface state, last change time, error counters, and relevant logs."
    esc = "Escalate to NOC/field team if the port is expected to be up."

    defaults = [
        f"• Meaning: {meaning}",
        f"• Top 2 likely causes (ranked): {causes}",
        f"• SAFE show commands: {cmd_block}",
        f"• Evidence to collect: {evidence}",
        f"• Escalation note: {esc}",
    ]

    # 5) If model output incomplete/empty → return defaults
    if len(bullets) < 5 or any(_is_empty_bullet(b) for b in bullets[:5]):
        # Use DOUBLE newlines so Streamlit/Markdown shows line-by-line nicely
        return "\n\n".join(defaults).strip()

    # 6) Otherwise return first 5 bullets, line-by-line
    return "\n\n".join(bullets[:5]).strip()


#  ACTIVE PROBLEM EXPLAIN 
def mistral_explain_problem(problem: dict) -> str:
    if not isinstance(problem, dict):
        return "⚠️ Problem payload must be a dictionary."

    try:
        severity = int(problem.get("severity", 0))
    except Exception:
        severity = 0

    name = (problem.get("name") or "N/A").strip()
    host = (problem.get("host") or "N/A")
    ip = (problem.get("ip") or "N/A")
    t = (problem.get("time") or "N/A")
    age = (problem.get("age") or "N/A")

    device_hint = (problem.get("device_hint") or "unknown").lower().strip()
    iface = (problem.get("iface") or "").strip()

    #  Smart Interface Extraction 
    if not iface:
        m = re.search(
            r"\b(?:Gi|GigabitEthernet|Fa|FastEthernet|Te|TenGigabitEthernet|Eth|Ethernet|Po|Port-channel|GE|XGigabitEthernet|Eth-Trunk|(?:\d{1,3}GE))\s*[\d/]+(?:\.\d+)?\b",
            name,
            flags=re.IGNORECASE
        )
        iface = m.group(0).replace(" ", "") if m else "N/A"

    iface_missing = (not iface) or (iface.strip().upper() == "N/A")

    # Device-aware command hint
    if device_hint == "asa":
        cmd_block = f"""
- show interface {iface}
- show interface {iface} | include line|protocol|error|drop
- show logging | include {iface}
""".strip() if not iface_missing else """
- show interface ip brief
- show logging | include LINK|down|up|error
""".strip()

    elif device_hint == "huawei":
        cmd_block = f"""
- display interface {iface}
- display interface brief | include {iface}
- display logbuffer | include {iface}
""".strip() if not iface_missing else """
- display interface brief
- display logbuffer | include LINK|down|UP|Error
""".strip()

    else:
        cmd_block = f"""
- show interface {iface}
- show logging | include {iface}
- show interface status | include {iface}
""".strip() if not iface_missing else """
- show ip interface brief
- show logging | include LINK|down|UP|ERR|disable
""".strip()

    prompt = f"""
You are a professional NOC engineer.

STRICT RULES:
- Use ONLY the given facts. Do NOT invent VLANs, configs, logs, root causes, or timelines.
- Do NOT suggest debug commands.
- If Interface is N/A, do NOT output interface-specific commands.
- Output MUST be EXACTLY 5 lines.
- Each line MUST start with "• " and MUST be COMPLETE (no empty bullets).
- SAFE show commands line MUST contain EXACTLY 3 commands separated by " ; " (single line).

FACTS:
- Name: {name}
- Severity: {severity}
- Host: {host}
- IP: {ip}
- Time: {t}
- Age: {age}
- Device hint: {device_hint}
- Interface: {iface}

ALLOWED causes (pick top 2 ONLY):
(1) physical disconnection/cable/transceiver
(2) remote device down/powered off
(3) admin shutdown
(4) port blocked/disabled by protection policy

Return EXACTLY 5 lines:
• Meaning: <1 short sentence>
• Top 2 likely causes (ranked): <(x), (y)>
• SAFE show commands: <cmd1 ; cmd2 ; cmd3>
• Evidence to collect: <short>
• Escalation note: <1 short sentence>

Use these SAFE commands (adapted to device hint):
{cmd_block}
""".strip()

    raw = _ollama_generate(prompt)
    return _normalize_5_bullets(raw, iface=iface, device_hint=device_hint)


def mistral_explain_cpu(host: str, ip: str, cpu: float) -> str:
    prompt = f"""
You are a SOC engineer. Use ONLY given facts.
Host: {host}
IP: {ip}
CPU: {cpu}%

Return 4 bullets: Meaning, 2 causes, Impact, Safe actions.
""".strip()
    return _ollama_generate(prompt)


def mistral_explain_memory(host: str, ip: str, memory: float) -> str:
    prompt = f"""
You are a SOC engineer. Use ONLY given facts.
Host: {host}
IP: {ip}
Memory: {memory}%

Return 4 bullets: Meaning, 2 causes, Impact, Safe actions.
""".strip()
    return _ollama_generate(prompt)


def mistral_explain_bandwidth(host: str, ip: str, bw: dict) -> str:
    if not isinstance(bw, dict):
        return "⚠️ Bandwidth payload must be dict."

    incoming = float(bw.get("in", 0.0) or 0.0)
    outgoing = float(bw.get("out", 0.0) or 0.0)
    total = float(bw.get("total", incoming + outgoing) or 0.0)

    prompt = f"""
You are a SOC network analyst. Use ONLY given facts.

Host: {host}
IP: {ip}
Time: {bw.get("time","N/A")}
In: {incoming:.2f} Mbps
Out: {outgoing:.2f} Mbps
Total: {total:.2f} Mbps

Return 5 short bullets: Meaning, Normal vs suspicious, Impact, Evidence, Actions.
""".strip()
    return _ollama_generate(prompt)


def mistral_explain_unreachable(host: str, ip: str, problem_name: str) -> str:
    prompt = f"""
    You are a SOC network engineer. Use ONLY given facts.
    Host: {host}
    IP: {ip}
    Problem: {problem_name}

    Return exactly 4 bullets:
    • Meaning: What this means in plain English.
    • Top 2 Causes: Top 2 network or physical reasons for device being unreachable.
    • Safe Checks: Suggest safe commands like ping, traceroute, or power check.
    • Escalation note: Who to contact if the device remains down.
    """.strip()
    return _ollama_generate(prompt)
