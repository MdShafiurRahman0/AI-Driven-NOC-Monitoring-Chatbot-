from zabbix_api import get_network_hosts, get_host_ip, get_active_problems
from datetime import datetime, timedelta


# Time Helper (BD Time)
def now_bd():
    return (datetime.utcnow() + timedelta(hours=6)).strftime("%Y-%m-%d %H:%M:%S")


# Existing Command Analyzer
def analyze_command(cmd: str) -> str:
    cmd = cmd.strip().lower()

    # DOWN
    if cmd == "down":
        problems = get_active_problems()
        hosts = get_network_hosts()
        now = datetime.utcnow()
        out = []

        for p in problems:
            if "down" not in p.get("name", "").lower():
                continue

            start = datetime.utcfromtimestamp(int(p.get("clock", 0)))
            mins = int((now - start).total_seconds() / 60)

            for h in hosts:
                ip = get_host_ip(h["hostid"])
                if ip and ip in p.get("name", ""):
                    out.append(
                        f"🔴 IP: {ip}\n"
                        f"   Host: {h['name']}\n"
                        f"   Down since: {mins} minutes\n"
                    )

        return "\n".join(out) if out else "✅ No IP is down"

    # SPECIFIC IP
    if cmd.startswith("ip "):
        target_ip = cmd.split(" ")[1]
        hosts = get_network_hosts()

        for h in hosts:
            ip = get_host_ip(h["hostid"])
            if ip == target_ip:
                return (
                    f"🖥 Host: {h['name']}\n"
                    f"IP: {ip}\n"
                    f"Checked at: {now_bd()}"
                )

        return "❌ IP not found"

    return "❓ Commands: down | ip <address>"


# IP SUMMARY FOR AI
def build_ip_summary(ip: str, problems: list) -> dict:
    """
    Build a structured summary for a given IP
    to be used by AI (Ollama / Mistral).
    """

    if not problems:
        return {
            "problem": "No active problems detected",
            "since": "N/A",
            "severity": "N/A",
            "cause": "System appears stable"
        }

    related_problem = None

    for p in problems:
        if ip in p.get("name", ""):
            related_problem = p
            break

    if not related_problem:
        return {
            "problem": "No active problems for this IP",
            "since": "N/A",
            "severity": "N/A",
            "cause": "No issue detected"
        }

    try:
        since = (
            datetime.utcfromtimestamp(int(related_problem.get("clock", 0)))
            + timedelta(hours=6)
        ).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        since = "Unknown time"

    return {
        "problem": related_problem.get("name", "Unknown problem"),
        "since": since,
        "severity": related_problem.get("severity", "N/A"),
        "cause": "Likely resource spike, network congestion, or service issue"
    }
