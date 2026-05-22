import re

def parse_command(cmd: str):
    cmd_raw = (cmd or "").strip()
    cmd = cmd_raw.lower()


    # FIREWALL 
    if re.search(r"\bfirewall(?:s)?\b|\bfmc\b|\bcisco\b", cmd):
        return "firewall"

        
    # IP explain pattern
    match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+explain", cmd)
    if match:
        return {
            "action": "ip_explain",
            "ip": match.group(1)
        }



    # SNMP DOWN 
    if cmd in [
        "snmp down",
        "snmpdown",
        "snmp problem",
        "snmp problems",
        "snmp alert",
        "snmp alerts",
        "snmp unreachable",
        "snmp timeout",
        "snmp not available",
        "snmp agent down",
        "snmp agent is not available",
    ]:
        return "snmp_down"









    # ACTIVE PROBLEMS
    if cmd in [
        "active problem",
        "active problems",
        "problems",
        "problem",
        "alerts",
        "alert"
    ]:
        return "active_problems"

    # EXPLAIN LAST PROBLEM
    if cmd in ["why explain?", "why explain"]:
        return {
            "action": "explain_last_problem"
        }

    # HOSTS
    if cmd in ["host", "hosts", "show host", "show hosts"]:
        return "hosts"

    # CPU (GLOBAL VIEW)
    if cmd in ["cpu", "cpu usage", "show cpu"]:
        return "cpu"

    # MEMORY (GLOBAL VIEW)
    if cmd in ["memory", "memory usage", "show memory"]:
        return "memory"

    # BANDWIDTH (GLOBAL VIEW)
    if cmd in ["bandwidth", "network", "network usage"]:
        return "bandwidth"

    # HOST-SPECIFIC METRICS 
    m = re.match(r"^(.+?)\s+(cpu|memory|mem|ram|bandwidth|bw|problems|problem|alerts|alert)$", cmd)
    if m:
        q = m.group(1).strip()
        metric = m.group(2).strip()

        if metric in ("mem", "ram"):
            metric = "memory"
        elif metric == "bw":
            metric = "bandwidth"
        elif metric in ("problem", "alerts", "alert"):
            metric = "problems"

        return {
            "action": "host_metric",
            "query": q,
            "metric": metric
        }

    # HOST ALL-IN-ONE
   
    if cmd and cmd not in ["unknown"]:
        return {
            "action": "host_all",
            "query": cmd_raw
        }

    return "unknown"
