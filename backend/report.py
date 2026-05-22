python3 - << 'EOF'
from zabbix_api import (
    get_network_hosts,
    get_host_ip,
    get_cpu_items,
    get_memory_items,
    get_bandwidth_in_items,
    get_bandwidth_out_items,
    get_active_problems
)
from datetime import datetime, timedelta

# TIME (Bangladesh, 12-hour) 

def now_bd():
    return (datetime.utcnow() + timedelta(hours=6)).strftime("%Y-%m-%d %I:%M:%S")

def zabbix_time_to_bd(ts):
    return (datetime.utcfromtimestamp(int(ts)) + timedelta(hours=6)).strftime(
        "%Y-%m-%d %I:%M:%S"
    )

# Helper Functions 

def max_item(items):
    valid = []
    for i in items:
        try:
            if float(i.get("lastvalue", 0)) > 0:
                valid.append(i)
        except:
            pass
    if not valid:
        return None
    return max(valid, key=lambda x: float(x["lastvalue"]))

def safe_value(items):
    if not items:
        return None
    val = items[0].get("lastvalue")
    if val in ("", None):
        return None
    return val

def bps_to_mbps(val):
    try:
        return round(float(val) / 1_000_000, 2)
    except:
        return 0.0

def bytes_to_mb_gb(val):
    try:
        val = float(val)
        mb = val / (1024 * 1024)
        if mb >= 1024:
            gb = mb / 1024
            return f"{round(gb, 2)} GB"
        else:
            return f"{round(mb, 2)} MB"
    except:
        return "N/A"

# Main Logic

hosts = get_network_hosts()
problems = get_active_problems()

print("\n================= HOST WISE FULL STATUS =================")

for h in hosts:
    print("\n=================================================")

    host_ip = get_host_ip(h["hostid"])

    print("Host        :", h["name"])
    print("IP Address  :", host_ip)
    print("Checked At  :", now_bd())

    #  METRIC
    cpu_items = get_cpu_items(h["hostid"])
    mem_items = get_memory_items(h["hostid"])

    cpu_val = safe_value(cpu_items)
    mem_val = safe_value(mem_items)

    bw_in  = max_item(get_bandwidth_in_items(h["hostid"]))
    bw_out = max_item(get_bandwidth_out_items(h["hostid"]))

    in_bps  = float(bw_in["lastvalue"]) if bw_in else 0
    out_bps = float(bw_out["lastvalue"]) if bw_out else 0
    total_bps = in_bps + out_bps

    print("CPU Usage     :", f"{cpu_val} %" if cpu_val else "N/A")
    print("Memory Usage  :", bytes_to_mb_gb(mem_val) if mem_val else "N/A")
    print("Bandwidth IN  :", f"{bps_to_mbps(in_bps)} Mbps")
    print("Bandwidth OUT :", f"{bps_to_mbps(out_bps)} Mbps")
    print("Bandwidth TOT :", f"{bps_to_mbps(total_bps)} Mbps")

    # PROBLEM
    host_problems = []

    for p in problems:
        if h["name"] in p["name"] or h["name"].split("-")[0] in p["name"]:
            host_problems.append(p)

    if not host_problems:
        print("Problems      : None 🎉")
    else:
        print("\nProblems:")
        for p in host_problems:
            print(
                f"""
  - Name        : {p['name']}
    Severity    : {p['severity']}
    Started At  : {zabbix_time_to_bd(p['clock'])}
    Acknowledged: {p['acknowledged']}
    Suppressed  : {p['suppressed']}
    Event ID    : {p['eventid']}
"""
            )
EOF
