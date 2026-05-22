import streamlit as st
import re
from datetime import datetime, timedelta
import streamlit.components.v1 as components
import yaml
from yaml.loader import SafeLoader
import streamlit_authenticator as stauth
from streamlit_extras.stylable_container import stylable_container
import os
import hashlib
import hmac
import secrets
import base64

st.set_page_config(
    page_title="DIU Data Center - NOC AI Chatbot",
    page_icon="🎓",
    layout="wide"
)

def inject_global_css():
    st.markdown("""
    <style>
    .stApp{ background: #F6F7FB; }
    .block-container{
      max-width: 1180px;
      margin: 0 auto;
      padding-top: 2.2rem;
      padding-bottom: 2rem;
      padding-left: 1.25rem;
      padding-right: 1.25rem;
     }
    .header-box {
        outline: 2px dashed red;
        padding: 16px;
        border-radius: 18px;
        border: 1px solid rgba(0,0,0,0.08);
        background: white;
        box-shadow: 0 10px 25px rgba(0,0,0,0.06);
    }
    .small-text {
        color:#6b7280;
        font-size:14px;
    }
    .live-badge {
        padding:4px 10px;
        border-radius:999px;
        background:rgba(16,185,129,0.12);
        border:1px solid rgba(16,185,129,0.25);
        color:#065f46;
        font-size:12px;
        font-weight:700;
    }

    div.stButton > button {
      border-radius: 14px !important;
      padding: 0.65rem 1rem !important;
      font-weight: 700 !important;
    }

    .topbar{
      width:100%;
      display:flex;
      justify-content:center;
      margin-top: 18px;
    }
    .topbar-inner{
      width:100%;
      max-width: 980px;
      background:#fff;
      border:1px solid rgba(0,0,0,0.08);
      border-radius: 18px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.06);
      padding: 18px 20px;
    }
    .brand{
      display:flex;
      align-items:center;
      justify-content:center;
      gap: 12px;
    }
    .brand-logo{
      height: 44px;
      width: auto;
    }
    .brand-title{
      font-size:24px;
      font-weight:800;
      text-align:center;
    }
    </style>
    """, unsafe_allow_html=True)

def render_header():
    st.markdown("""
    <div class="topbar">
      <div class="topbar-inner">
        <div class="brand">
          <img class="brand-logo" src="data:image/png;base64,{{LOGO_B64}}" alt="DIU">
          <div class="brand-title">
            Data Center NOC – AI Chatbot <span class="live-badge">LIVE</span>
          </div>
        </div>
      </div>
    </div>
    """.replace("{{LOGO_B64}}", st.session_state.get("diu_logo_b64","")), unsafe_allow_html=True)
    st.divider()


#  COOKIE LOGIN
USERS_DB_PATH = "users_db.yaml"

def _load_auth_config():
    with open(USERS_DB_PATH, "r") as f:
        return yaml.load(f, Loader=SafeLoader) or {}

config = _load_auth_config()

authenticator = stauth.Authenticate(
    config["credentials"],
    config["cookie"]["name"],
    config["cookie"]["key"],
    config["cookie"]["expiry_days"],
)

# HEADER LOAD (CORRECT PLACE)

inject_global_css()

if "diu_logo_b64" not in st.session_state:
    try:
        with open("diu.png", "rb") as f:
            st.session_state["diu_logo_b64"] = base64.b64encode(f.read()).decode()
    except FileNotFoundError:
        st.session_state["diu_logo_b64"] = ""

render_header()

authenticator.login(location="main")

auth_status = st.session_state.get("authentication_status")
name = st.session_state.get("name")
username = st.session_state.get("username")

if auth_status is False:
    st.error("❌ Invalid username or password")
    st.stop()
elif auth_status is None:
    st.info("Please login")
    st.stop()



with st.sidebar:
    st.markdown("### 👤 Session")
    st.caption("Status: ✅ Logged in")
    authenticator.logout(location="sidebar")

uobj = (config.get("credentials", {}).get("usernames", {}) or {}).get(username, {})

st.session_state["current_user"] = {
    "username": username,
    "name": uobj.get("name", username),
    "role": uobj.get("role", "user"),
}

role = st.session_state["current_user"].get("role", "")


# Database Helper Functions
def _load_users_db():
    if not os.path.exists(USERS_DB_PATH):
        return {"users": {}}
    try:
        with open(USERS_DB_PATH, "r") as f:
            data = yaml.safe_load(f) or {}
        if "users" not in data or not isinstance(data["users"], dict):
            data["users"] = {}
        return data
    except Exception:
        return {"users": {}}

def _save_users_db(data: dict):
    with open(USERS_DB_PATH, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False)

def _hash_password_pbkdf2(password: str, iterations: int = 200_000) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (
        iterations,
        base64.b64encode(salt).decode("utf-8"),
        base64.b64encode(dk).decode("utf-8"),
    )

def _verify_password_pbkdf2(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_b64, hash_b64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iters)
        salt = base64.b64decode(salt_b64.encode("utf-8"))
        expected = base64.b64decode(hash_b64.encode("utf-8"))
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def admin_panel_ui():
    st.sidebar.markdown("### 🛠️ Admin Panel")

    db = _load_users_db()
    
    if "credentials" not in db:
        db["credentials"] = {"usernames": {}}
    if "usernames" not in db["credentials"]:
        db["credentials"]["usernames"] = {}

    users = db["credentials"]["usernames"]

    with st.sidebar.expander("👥 Manage Users", expanded=False):
        tab1, tab2, tab3 = st.tabs(["Create", "Reset", "Delete"])

        with tab1:
            with st.form("create_user_form"):
                new_username = st.text_input("Username", placeholder="e.g. socuser1")
                new_name = st.text_input("Full name", placeholder="e.g. Operator One")
                new_role = st.selectbox("Role", ["user", "viewer", "admin"], index=0)
                new_pass = st.text_input("Password", type="password", placeholder="Set a strong password")
                confirm = st.text_input("Confirm password", type="password", placeholder="Re-type password")
                ok = st.form_submit_button("✅ Create User", use_container_width=True)

                if ok:
                    new_username = (new_username or "").strip()
                    if not new_username:
                        st.error("Username required")
                    elif new_username in users:
                        st.error("Username already exists")
                    elif not new_pass or len(new_pass) < 6:
                        st.error("Password must be at least 6 characters")
                    elif new_pass != confirm:
                        st.error("Password mismatch")
                    else:
                        hashed_pass = stauth.Hasher.hash(new_pass)
                        users[new_username] = {
                            "name": (new_name or new_username).strip(),
                            "role": new_role,
                            "password": hashed_pass,
                        }
                        db["credentials"]["usernames"] = users
                        _save_users_db(db)
                        st.success(f"User created: {new_username} (Please refresh the page)")

        with tab2:
            if users:
                target = st.selectbox("Select user", sorted(users.keys()))
                with st.form("reset_pass_form"):
                    p1 = st.text_input("New password", type="password")
                    p2 = st.text_input("Confirm new password", type="password")
                    ok2 = st.form_submit_button("🔁 Reset Password", use_container_width=True)
                    if ok2:
                        if not p1 or len(p1) < 6:
                            st.error("Password must be at least 6 characters")
                        elif p1 != p2:
                            st.error("Password mismatch")
                        else:
                            users[target]["password"] = stauth.Hasher([p1]).generate()[0]
                            db["credentials"]["usernames"] = users
                            _save_users_db(db)
                            st.success(f"Password reset for: {target}")
            else:
                st.info("No users yet.")

        with tab3:
            if users:
                del_user = st.selectbox("Delete user", sorted(users.keys()), key="del_user_select")
                with st.form("delete_user_form"):
                    sure = st.checkbox("I understand this will delete the user")
                    ok3 = st.form_submit_button("🗑️ Delete", use_container_width=True)
                    if ok3:
                        if not sure:
                            st.error("Please confirm deletion")
                        else:
                            users.pop(del_user, None)
                            db["credentials"]["usernames"] = users
                            _save_users_db(db)
                            st.success(f"Deleted user: {del_user}")
            else:
                st.info("No users to delete.")



if role == "admin":
    admin_panel_ui()

# SESSION INIT
if "selected_host" not in st.session_state:
    st.session_state.selected_host = None

if "ai_bw" not in st.session_state:
    st.session_state.ai_bw = {}

if "cmd_input" not in st.session_state:
    st.session_state.cmd_input = ""

if "view" not in st.session_state:
    st.session_state.view = "none"

if "problems" not in st.session_state:
    st.session_state.problems = []

if "ai_result" not in st.session_state:
    st.session_state.ai_result = ""

if "selected_host_query" not in st.session_state:
    st.session_state.selected_host_query = ""

if "selected_host_metric" not in st.session_state:
    st.session_state.selected_host_metric = None


# IMPORTS

from zabbix_api import (
    get_network_hosts,
    get_active_problems,
    get_host_ip,
    get_cpu_summary,
    get_memory_summary,
    get_bandwidth_summary,
    get_bandwidth_bulk,
    get_host_by_ip,
    get_host_by_name_query,
    get_active_problems_by_host,
    search_hosts_by_query,
    get_active_problems_detailed,
    get_snmp_down_hosts,
  )

from command_parser import parse_command
from agent import explain_ip

from llm_engine import (
    mistral_explain_problem,
    mistral_explain_cpu,
    mistral_explain_memory,
    mistral_explain_bandwidth,
    mistral_explain_unreachable
)

#  CACHED HELPERS
@st.cache_data(ttl=5)
def cached_hosts():
    return get_network_hosts()

@st.cache_data(ttl=15)
def cached_bandwidth(hostid, window_sec=300):
    return get_bandwidth_summary(hostid, window_sec=window_sec)

@st.cache_data(ttl=15)
def cached_bandwidth_bulk(hostids_tuple):
    return get_bandwidth_bulk(list(hostids_tuple))

@st.cache_data(ttl=5)
def cached_cpu(hostid):
    return get_cpu_summary(hostid)

@st.cache_data(ttl=5)
def cached_memory(hostid):
    return get_memory_summary(hostid)

@st.cache_data(ttl=10)
def cached_problems_by_host(hostid):
    return get_active_problems_by_host(hostid)

@st.cache_data(ttl=20)
def cached_active_problems_detailed(limit=200):
    return get_active_problems_detailed(limit)


# MAIN DASHBOARD HEADER 
st.subheader("NOC AI Dashboard")
st.caption("Type a command or use quick actions below.")




# HELPERS
def cpu_status(cpu):
    if cpu < 50:
        return "🟢 Normal"
    elif cpu < 70:
        return "🟠 High"
    else:
        return "🔴 Critical"

def memory_status(mem):
    return "🟢 Normal" if mem < 60 else "🟠 High" if mem < 80 else "🔴 Critical"

GROUP_RULES = [
    ("Core",            [r"\bcore\b", r"core_router", r"core-router", r"core-sw", r"core\s*sw"]),
    ("Firewall",        [r"\bfirewall\b"]),
    ("ISP",             [r"\bisp\b"]),
    ("Data Center",     [r"data[-\s]?center", r"\bdc\b", r"server-r\d+", r"\bems\b"]),
    ("ESXi/HX/vCenter", [r"\besxi\b", r"\bvcenter\b", r"\bhx-\d+\b", r"diu-hx", r"\bhx\b"]),
    ("AB4",             [r"\bab4\b"]),
    ("AB3",             [r"\bab3\b"]),
    ("Engineering",     [r"engineering", r"engr\.", r"engr\s", r"\bcomplex\b"]),
    ("DNS/NTP",         [r"\bdns\b", r"\bntp\b"]),
    ("Server/DB",       [r"\bdb\b", r"dspace", r"backup", r"rimu"]),
    ("CCTV",            [r"\bcctv\b"]),
    ("Campus/Office",   [r"admission", r"civil", r"studio", r"apartment", r"control\s*room"]),
]

def detect_group(hostname: str) -> str:
    h = (hostname or "").strip().lower()
    for group, patterns in GROUP_RULES:
        for ptn in patterns:
            if re.search(ptn, h):
                return group
    return "Others"

def group_hosts(hosts):
    grouped = {}
    for h in hosts:
        g = detect_group(h.get("name", ""))
        grouped.setdefault(g, []).append(h)
    return grouped


# COMMAND EXECUTOR

def execute_command(cmd: str):
    cmd = (cmd or "").strip()

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", cmd):
        st.session_state.selected_ip = cmd
        st.session_state.view = "host_detail"
        return

    action = parse_command(cmd)

    if isinstance(action, dict) and action.get("action") in ("host_all", "host_metric"):
        st.session_state.selected_host_query = action.get("query", "")
        st.session_state.selected_host_metric = action.get("metric", None)
        st.session_state.view = "host_search"
        return

    if action == "hosts":
        st.session_state.view = "hosts"
        return

    if action == "snmp_down":
        st.session_state.problems = get_snmp_down_hosts(limit=1000, include_unknown=False)
        st.session_state.view = "snmp_down"
        return

    if action in ["problems", "active_problems"]:
        st.session_state.problems = get_active_problems()
        st.session_state.view = "active_problems"
        return

    if action == "cpu":
        st.session_state.view = "cpu"
        return

    if action == "memory":
        st.session_state.view = "memory"
        return

    if action == "bandwidth":
        st.session_state.view = "bandwidth"
        return

    if isinstance(action, dict) and action.get("action") == "ip_explain":
        with st.spinner("Analyzing IP with AI..."):
            st.session_state.ai_result = explain_ip(action["ip"])
        st.session_state.view = "ai"
        return

    st.session_state.view = "unknown"



# COMMAND CONSOLE 


st.markdown("### Hello, What do you want to know?")

with st.form("cmd_form", clear_on_submit=False):
    c1, c2 = st.columns([6, 1.6], vertical_alignment="bottom")

    with c1:
        st.text_input(
            "Enter command",
            key="cmd_input",
            label_visibility="collapsed",
            placeholder="hosts | active problems | cpu | memory | bandwidth | <ip> explain | isp/core/ab3/ab4 | link down"
        )

    with c2:
        run = st.form_submit_button("🚀 Run", use_container_width=True)

    if run:
        execute_command(st.session_state.cmd_input.strip())

# QUICK ACTIONS


st.markdown("### Quick Actions")
q1, q2, q3, q4,q5 = st.columns(5)

with q1:
    if st.button("📡 Hosts", use_container_width=True):
        execute_command("hosts")

with q2:
    if st.button("🚨 Active Problems", use_container_width=True):
        execute_command("active problems")

with q3:
    if st.button("🔥 CPU", use_container_width=True):
        execute_command("cpu")

with q4:
    if st.button("🌐 Bandwidth", use_container_width=True):
        execute_command("bandwidth")

with q5:
    if st.button("📶 SNMP Down", use_container_width=True):
        execute_command("snmp down")

st.write("")


# OUTPUT

if st.session_state.view == "hosts":
    st.subheader("📡 Network Hosts")
    for idx, h in enumerate(cached_hosts(), start=1):
        ip = get_host_ip(h["hostid"])
        st.write(f"🖥️ **{h['name']}** — `{ip}`")

elif st.session_state.view == "firewall":
    show_firewalls()

elif st.session_state.view == "snmp_down":
    st.subheader("📶 SNMP Down — Affected Hosts")

    rows = st.session_state.problems or []
    if not rows:
        st.success("✅ No SNMP down hosts found.")
    else:
        st.caption(f"Total SNMP down hosts: {len(rows)}")

        for r in rows:
            host = r.get("host", "N/A")
            ip = r.get("ip", "N/A")
            err = (r.get("error") or "").strip()
            av = r.get("available")

            status = "🔴 DOWN" if av == "2" else "🟠 UNKNOWN"

            st.write(f"{status} — **{host}** — `{ip}`")
            if err:
                st.caption(f"Reason: {err}")
            else:
                st.caption("Reason: No error message from Zabbix interface.")


# === WhatsApp Alert Section Start ===
            import urllib.parse
            import hashlib
            import streamlit.components.v1 as components
            
            unique_id = hashlib.md5(f"snmp_{host}_{ip}".encode()).hexdigest()

            with st.expander("📲 Send Alert to WhatsApp"):
                message = (
                    f"🚨 *NOC ALERT - SNMP DOWN*\n\n"
                    f"🛑 *Host:* {host}\n"
                    f"🌐 *IP:* {ip}\n"
                    f"ℹ️ *Reason:* {err if err else 'N/A'}\n\n"
                    f"⚠️ *Please check ASAP!*"
                )
                
                encoded_msg = urllib.parse.quote(message.encode('utf-8'))
                
                html_code = f"""
                <!DOCTYPE html>
                <html>
                <head>
                <style>
                body {{ font-family: sans-serif; margin: 0; padding: 0; background-color: transparent; }}
                .container {{ display: flex; align-items: center; gap: 10px; padding: 2px; }}
                input {{ padding: 8px 12px; border: 1px solid #ccc; border-radius: 6px; font-size: 14px; width: 200px; outline: none; }}
                input:focus {{ border-color: #25D366; }}
                button {{ padding: 8px 16px; background-color: #25D366; color: white; border: none; border-radius: 6px; font-size: 14px; font-weight: bold; cursor: pointer; transition: 0.2s; white-space: nowrap; }}
                button:hover {{ background-color: #1DA851; }}
                </style>
                </head>
                <body>
                <div class="container">
                    <input type="text" id="phone_input" placeholder="017XXXXXXXX" autocomplete="off" />
                    <button onclick="openWA()">💬 Open in WhatsApp</button>
                </div>
                <script>
                function openWA() {{
                    let phone = document.getElementById('phone_input').value;
                    phone = phone.replace(/\D/g, ''); 
                    if (phone.length === 11 && phone.startsWith('01')) {{
                        phone = '88' + phone;
                    }}
                    if (phone.length >= 11) {{
                        let url = "https://api.whatsapp.com/send?phone=" + phone + "&text={encoded_msg}";
                        window.open(url, '_blank');
                    }} else {{
                        alert("Please enter a valid phone number!");
                    }}
                }}

                document.getElementById('phone_input').addEventListener('keypress', function (e) {{
                    if (e.key === 'Enter') {{
                        openWA();
                    }}
                }});
                </script>
                </body>
                </html>
                """
                
                components.html(html_code, height=55)
                
            st.divider()
            # === WhatsApp Alert Section End ===

            
elif st.session_state.view == "host_detail":
    ip = st.session_state.selected_ip.strip()
    st.subheader(f"🧩 Host Detail (SOC View) — {ip}")

    host = get_host_by_ip(ip)
    if not host:
        st.error("❌ No IP Match")
    else:
        hostid = host["hostid"]
        name = host["name"]

        cpu = cached_cpu(hostid)
        mem = cached_memory(hostid)
        bw = cached_bandwidth(hostid, window_sec=300)
        if bw is None:
            bw = {"in": 0.0, "out": 0.0, "total": 0.0, "time": "Collecting..."}

        problems = cached_problems_by_host(hostid) or []

        c1m, c2m, c3m, c4m = st.columns(4)
        c1m.metric("Host", name)
        c2m.metric("CPU %", "-" if cpu is None else f"{cpu:.1f}")
        c3m.metric("Memory %", "-" if mem is None else f"{mem:.1f}")

        total = bw.get("total")
        if total is None:
            total = (bw.get("in") or bw.get("rx") or 0) + (bw.get("out") or bw.get("tx") or 0)

        c4m.metric("Total Mbps", f"{total:.2f}")

        st.markdown("### 🌐 Bandwidth")
        st.write(f"Time: {bw.get('time','Collecting...')}")
        st.write(f"Incoming: {bw.get('in',0.0):.2f} Mbps")
        st.write(f"Outgoing: {bw.get('out',0.0):.2f} Mbps")
        st.write(f"Total: {bw.get('total',0.0):.2f} Mbps")

        st.markdown("### 🚨 Active Problems")
        if not problems:
            st.success("✅ No active problems for this host")
        else:
            for p in problems:
                st.write(f"🔴 Sev {p.get('severity','?')} — {p.get('name','N/A')}")

        if st.button("🧠 Explain this host with AI", key=f"ai_host_{hostid}"):
            with st.spinner("AI analyzing host status..."):
                st.session_state.ai_result = mistral_explain_bandwidth(
                    name,
                    ip,
                    {"in": bw.get("in",0.0), "out": bw.get("out",0.0), "total": bw.get("total",0.0), "time": bw.get("time","")}
                )
            st.session_state.view = "ai"

elif st.session_state.view == "host_search":
    q = (st.session_state.get("selected_host_query") or "").strip()
    metric = st.session_state.get("selected_host_metric")

    matches = search_hosts_by_query(q)

    if not matches:
        one = get_host_by_name_query(q)
        if one and one.get("hostid"):
            matches = [{"hostid": one["hostid"], "name": one.get("name", "N/A")}]

    if not matches:
        st.subheader(f"🔎 Problem Search: {q}")

        limit = st.slider("Max problems to load", 20, 500, 200)
        problems = cached_active_problems_detailed(limit) or []

        ql = q.strip().lower()
        problems = [p for p in problems if ql in (p.get("name", "").lower())]

        if not problems:
            st.error(f"❌ No host found and no problem matched for: {q}")
        else:
            def _sev(p):
                try:
                    return int(p.get("severity", 0))
                except Exception:
                    return 0

            def _clk(p):
                try:
                    return int(p.get("clock", 0))
                except Exception:
                    return 0

            def _fmt_time(clk):
                if not clk:
                    return "N/A"
                return (datetime.utcfromtimestamp(int(clk)) + timedelta(hours=6)).strftime("%Y-%m-%d %I:%M:%S %p")

            def _age_label(clk):
                if not clk:
                    return "Unknown"
                now_ts = int(datetime.utcnow().timestamp())
                age_min = max(0, (now_ts - int(clk)) // 60)
                age_hr = age_min // 60
                age_days = age_hr // 24
                if age_days < 1:
                    return f"🟢 Fresh (<24h) — {age_hr}h"
                if age_days <= 7:
                    return f"🟠 Stale (1–7d) — {age_days}d"
                return f"🔴 Very Old (>7d) — {age_days}d"

            def run_llm_safe(prompt: str) -> str:
                try:
                    fn = globals().get("mistral_explain_problem")
                    if callable(fn):
                        return fn(prompt)
                    for fn_name in ["ask_llm", "llm_chat", "mistral_chat", "ollama_chat", "generate_llm_response"]:
                        f = globals().get(fn_name)
                        if callable(f):
                            return f(prompt)
                    return "⚠️ LLM function not found. Map run_llm_safe() to your LLM call."
                except Exception as e:
                    return f"⚠️ LLM error: {e}"

            def build_problem_explain_prompt(pname: str, sev: int, host_label: str, ip_addr: str, clk: int) -> str:
                t = _fmt_time(clk)
                a = _age_label(clk)
                return f"""
You are a network/SOC assistant. Explain this specific monitoring problem clearly and accurately.

Problem:
- Severity: {sev}
- Title: {pname}
- Host: {host_label}
- IP: {ip_addr}
- Time: {t}
- Age: {a}

Give:
1) What it likely means (plain language)
2) Most common root causes (ranked)
3) Immediate checks (switchport status, physical, vlan, err-disable, power, etc.)
4) Safe action plan (what to verify/escalate)
Keep it concise but actionable.
""".strip()

            grouped = {}
            for p in problems:
                hosts = p.get("hosts") or []
                if not hosts:
                    grouped.setdefault("Others", []).append({"p": p, "h": None})
                    continue
                for hh in hosts:
                    g = detect_group(hh.get("name", ""))
                    grouped.setdefault(g, []).append({"p": p, "h": hh})

            for gname in sorted(grouped.keys()):
                rows = grouped[gname]
                rows = sorted(rows, key=lambda r: (_sev(r["p"]), _clk(r["p"])), reverse=True)

                with st.expander(
                    f"📁 {gname} — {len(rows)} matched",
                    expanded=(gname in ("Core", "Firewall", "ISP"))
                ):
                    for r in rows[:200]:
                        p = r["p"]
                        hh = r["h"]

                        pname = p.get("name", "N/A")
                        sev = _sev(p)
                        clk = _clk(p)

                        host_label = "Unknown host"
                        ip = "N/A"
                        if hh and hh.get("hostid"):
                            host_label = hh.get("name", "N/A")
                            try:
                                ip = get_host_ip(hh["hostid"]) or "N/A"
                            except Exception:
                                ip = "N/A"

                        pid = str(p.get("eventid") or p.get("event_id") or f"{clk}_{host_label}_{sev}")

                        left, right = st.columns([0.82, 0.18])

                        with left:
                            st.write(f"• **Sev {sev}** — {pname}")
                            st.caption(
                                f"Host: {host_label}  |  IP: {ip}  |  Time: {_fmt_time(clk)}  |  Age: {_age_label(clk)}"
                            )


                       

                                 
                                                        
                        with right:
                            if st.button("🧠 AI Explain", key=f"ps_ai_{pid}"):
                                text_lower = (pname or "").lower()
                                
                                with st.spinner("AI analyzing problem..."):
                                    if "cpu" in text_lower or "processor" in text_lower:
                                        st.session_state[f"ps_ai_out_{pid}"] = mistral_explain_cpu(host_label, ip, 100.0)
                                        
                                    elif "memory" in text_lower or "ram" in text_lower:
                                        st.session_state[f"ps_ai_out_{pid}"] = mistral_explain_memory(host_label, ip, 100.0)

                                    elif "reachable" in text_lower or "icmp" in text_lower or "ping" in text_lower:
                                        st.session_state[f"ps_ai_out_{pid}"] = mistral_explain_unreachable(host_label, ip, pname)  
                                        
                                    else:
                                        if "asav" in text_lower:
                                            device_hint = "asa"
                                        elif "huawei" in text_lower or "vrp" in text_lower:
                                            device_hint = "huawei"
                                        else:
                                            device_hint = "switch"

                                        m = re.search(
                                            r"\b(?:Te|Gi|Fa|Eth|Po|GE|XGE)\d+(?:/\d+){1,3}\b",
                                            pname or "",
                                            re.IGNORECASE
                                        )
                                        iface = m.group(0) if m else "N/A"

                                        payload = {
                                            "name": pname,
                                            "severity": sev,
                                            "host": host_label,
                                            "ip": ip,
                                            "time": _fmt_time(clk),
                                            "age": _age_label(clk),
                                            "device_hint": device_hint,
                                            "iface": iface,
                                        }
                                        st.session_state[f"ps_ai_out_{pid}"] = mistral_explain_problem(payload)

                        out_key = f"ps_ai_out_{pid}"
                        if st.session_state.get(out_key):
                            with st.expander("AI Explanation", expanded=True):
                                st.markdown(st.session_state[out_key])

                               
                       
    else:
        window_sec = st.session_state.get("bw_window_sec", 300)
        st.subheader(f"🔎 Results for: {q} — {len(matches)} host(s)")

        for i, h in enumerate(matches, start=1):
            hostid = h["hostid"]
            name = h.get("name", "N/A")
            ip = get_host_ip(hostid)

            def _cpu():
                cpu = cached_cpu(hostid)
                st.markdown("### 🔥 CPU")
                st.write("- **CPU %:** " + ("-" if cpu is None else f"{cpu:.1f}"))
                if cpu is not None:
                    st.write("- **Status:** " + cpu_status(cpu))

            def _mem():
                mem = cached_memory(hostid)
                st.markdown("### 🧠 Memory")
                st.write("- **Memory %:** " + ("-" if mem is None else f"{mem:.1f}"))
                if mem is not None:
                    st.write("- **Status:** " + memory_status(mem))

            def _bw():
                bw = cached_bandwidth(hostid, window_sec=window_sec)
                if bw is None:
                    bw = {
                        "in_avg": 0.0, "out_avg": 0.0, "total_avg": 0.0,
                        "in_inst": 0.0, "out_inst": 0.0, "total_inst": 0.0,
                        "time": "Collecting..."
                    }
                st.markdown("### 🌐 Bandwidth")
                st.write(f"Time: {bw.get('time','Collecting...')}")
                st.write(f"Incoming: {float(bw.get('in_avg') or 0.0):.2f} Mbps (avg) | {float(bw.get('in_inst') or 0.0):.2f} Mbps (instant)")
                st.write(f"Outgoing: {float(bw.get('out_avg') or 0.0):.2f} Mbps (avg) | {float(bw.get('out_inst') or 0.0):.2f} Mbps (instant)")
                st.write(f"Total: {float(bw.get('total_avg') or 0.0):.2f} Mbps (avg) | {float(bw.get('total_inst') or 0.0):.2f} Mbps (instant)")

            def _problems():
                st.markdown("### 🚨 Active Problems")
                problems = cached_problems_by_host(hostid) or []
                if not problems:
                    st.success("✅ No active problems for this host")
                else:
                    for p in problems:
                        st.write(f"🔴 Sev {p.get('severity','?')} — {p.get('name','N/A')}")

            with st.expander(f"🖥️ {name} ({ip})", expanded=(i <= 2)):
                if metric is None:
                    t1, t2, t3, t4 = st.tabs(["CPU", "Memory", "Bandwidth", "Problems"])
                    with t1:
                        _cpu()
                    with t2:
                        _mem()
                    with t3:
                        _bw()
                    with t4:
                        _problems()
                else:
                    if metric == "cpu":
                        _cpu()
                    elif metric == "memory":
                        _mem()
                    elif metric == "bandwidth":
                        _bw()
                    elif metric == "problems":
                        _problems()

elif st.session_state.view == "active_problems":
    st.subheader("🚨 Active Problems (SOC View)")

    problems = st.session_state.problems or []
    all_problems = list(problems)
    filtered_problems = list(problems)

    if not problems:
        st.success("✅ No active problems")
    else:
        q = st.text_input(
            "Search problem",
            value="",
            placeholder="e.g. Link down | ICMP | High bandwidth"
        )
        show_limit = st.slider("Max items to show", 10, 200, 80)

        age_mode = st.radio(
            "Show by age",
            ["All", "Fresh (<24h)", "Stale (1–7d)", "Very Old (>7d)"],
            horizontal=True,
            index=0
        )

        def _sev(p):
            try:
                return int(p.get("severity", 0))
            except Exception:
                return 0

        def _clk(p):
            try:
                return int(p.get("clock", 0))
            except Exception:
                return 0

        overall_total = len(all_problems)
        overall_sev4 = sum(1 for p in all_problems if _sev(p) == 4)
        overall_sev3 = sum(1 for p in all_problems if _sev(p) == 3)
        overall_sev2 = sum(1 for p in all_problems if _sev(p) == 2)
        overall_sev1 = sum(1 for p in all_problems if _sev(p) == 1)

        st.caption(
            f"Overall (All): Total {overall_total} | Sev4 {overall_sev4} | Sev3 {overall_sev3} | Sev2 {overall_sev2} | Sev1 {overall_sev1}"
        )

        if q.strip():
            ql = q.strip().lower()
            filtered_problems = [p for p in filtered_problems if ql in (p.get("name", "").lower())]

        filtered_problems = sorted(
            filtered_problems,
            key=lambda p: (_sev(p), _clk(p)),
            reverse=True
        )[:show_limit]

        total = len(filtered_problems)
        sev4 = sum(1 for p in filtered_problems if _sev(p) == 4)
        sev3 = sum(1 for p in filtered_problems if _sev(p) == 3)
        sev2 = sum(1 for p in filtered_problems if _sev(p) == 2)
        sev1 = sum(1 for p in filtered_problems if _sev(p) == 1)

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total (Filtered)", total)
        c2.metric("Sev 4", sev4)
        c3.metric("Sev 3", sev3)
        c4.metric("Sev 2", sev2)
        c5.metric("Sev 1", sev1)

        groups = {4: [], 3: [], 2: [], 1: [], 0: []}
        for p in filtered_problems:
            groups[_sev(p)].append(p)

        def sev_label(sev):
            if sev == 4:
                return "🟥 Severity 4 (Disaster)"
            if sev == 3:
                return "🟥 Severity 3 (High)"
            if sev == 2:
                return "🟧 Severity 2 (Average)"
            if sev == 1:
                return "🟨 Severity 1 (Warning)"
            return "⬜ Others"

        for sev in [4, 3, 2, 1, 0]:
            if not groups[sev]:
                continue

            with st.expander(f"{sev_label(sev)} — {len(groups[sev])} issues", expanded=(sev >= 3)):
                for p in groups[sev]:
                    name = p.get("name", "N/A")
                    clk = _clk(p)

                    t = "N/A"
                    if clk:
                        t = (datetime.utcfromtimestamp(clk) + timedelta(hours=6)).strftime("%Y-%m-%d %I:%M:%S %p")

                    age_label = "Unknown"
                    age_days = None
                    age_hr = 0

                    if clk:
                        now_ts = int(datetime.utcnow().timestamp())
                        age_min = max(0, (now_ts - int(clk)) // 60)
                        age_hr = age_min // 60
                        age_days = age_hr // 24

                        if age_days < 1:
                            age_label = f"🟢 Fresh (<24h) — {age_hr}h"
                        elif age_days <= 7:
                            age_label = f"🟠 Stale (1–7d) — {age_days}d"
                        else:
                            age_label = f"🔴 Very Old (>7d) — {age_days}d"

                    if age_mode == "Fresh (<24h)":
                        if age_days is None or age_days >= 1:
                            continue
                    elif age_mode == "Stale (1–7d)":
                        if age_days is None or not (1 <= age_days <= 7):
                            continue
                    elif age_mode == "Very Old (>7d)":
                        if age_days is None or age_days <= 7:
                            continue

                  



                    # Unique ID for this specific problem
                    pid = str(p.get("eventid") or p.get("event_id") or f"{clk}_{name}_{sev}")

                    col1, col2 = st.columns([0.82, 0.18])
                    
                    with col1:
                        st.write(f"• {name}")
                        st.caption(f"Time: {t}  |  Age: {age_label}")
                    
                    with col2:
                        if st.button("🧠 AI Explain", key=f"ap_ai_{pid}"):
                            # Interface and Device Hint Logic
                            text_lower = (name or "").lower()
                            
                            with st.spinner("AI analyzing problem..."):
                                if "cpu" in text_lower or "processor" in text_lower:
                                    st.session_state[f"ap_ai_out_{pid}"] = mistral_explain_cpu(p.get("host", "N/A"), p.get("ip", "N/A"), 100.0)
                                    
                                elif "memory" in text_lower or "ram" in text_lower:
                                    st.session_state[f"ap_ai_out_{pid}"] = mistral_explain_memory(p.get("host", "N/A"), p.get("ip", "N/A"), 100.0)

                                elif "reachable" in text_lower or "icmp" in text_lower or "ping" in text_lower:
                                    st.session_state[f"ap_ai_out_{pid}"] = mistral_explain_unreachable(p.get("host", "N/A"), p.get("ip", "N/A"), name)
                                    
                                else:
                                    if "asav" in text_lower:
                                        device_hint = "asa"
                                    elif "huawei" in text_lower or "vrp" in text_lower:
                                        device_hint = "huawei"
                                    else:
                                        device_hint = "switch"

                                    m = re.search(r"\b(?:Te|Gi|Fa|Eth|Po|GE|XGE)\d+(?:/\d+){1,3}\b", name or "", re.IGNORECASE)
                                    iface = m.group(0) if m else "N/A"

                                    payload = {
                                        "name": name,
                                        "severity": sev,
                                        "host": p.get("host", "N/A"),
                                        "ip": p.get("ip", "N/A"),
                                        "time": t,
                                        "age": age_label,
                                        "device_hint": device_hint,
                                        "iface": iface,
                                    }
                                    st.session_state[f"ap_ai_out_{pid}"] = mistral_explain_problem(payload)

                    # AI Explanation display
                    out_key = f"ap_ai_out_{pid}"
                    if st.session_state.get(out_key):
                        with st.expander("AI Explanation", expanded=True):
                            st.markdown(st.session_state[out_key])









# === WhatsApp Alert Section Start
                    import urllib.parse
                    import streamlit.components.v1 as components
                    
                    with st.expander("📲 Send Alert to WhatsApp"):
                        message = (
                            f"🚨 *NOC ALERT*\n\n"
                            f"🛑 *Issue:* {name}\n"
                            f"📅 *Time:* {t}\n"
                            f"⏳ *Age:* {age_label}\n\n"
                            f"⚠️ *Please check ASAP!*"
                        )


                        encoded_msg = urllib.parse.quote(message.encode('utf-8'))
                        
                        html_code = f"""
                        <!DOCTYPE html>
                        <html>
                        <head>
                        <style>
                        body {{ font-family: sans-serif; margin: 0; padding: 0; background-color: transparent; }}
                        .container {{ display: flex; align-items: center; gap: 10px; padding: 2px; }}
                        input {{ padding: 8px 12px; border: 1px solid #ccc; border-radius: 6px; font-size: 14px; width: 200px; outline: none; }}
                        input:focus {{ border-color: #25D366; }}
                        button {{ padding: 8px 16px; background-color: #25D366; color: white; border: none; border-radius: 6px; font-size: 14px; font-weight: bold; cursor: pointer; transition: 0.2s; white-space: nowrap; }}
                        button:hover {{ background-color: #1DA851; }}
                        </style>
                        </head>
                        <body>
                        <div class="container">
                            <input type="text" id="phone_input" placeholder="017XXXXXXXX" autocomplete="off" />
                            <button onclick="openWA()">💬 Open in WhatsApp</button>
                        </div>
                        <script>
                        function openWA() {{
                            let phone = document.getElementById('phone_input').value;
                            phone = phone.replace(/\D/g, ''); 
                            if (phone.length === 11 && phone.startsWith('01')) {{
                                phone = '88' + phone;
                            }}
                            if (phone.length >= 11) {{
                                let url = "https://api.whatsapp.com/send?phone=" + phone + "&text={encoded_msg}";
                                window.open(url, '_blank');
                            }} else {{
                                alert("Please enter a valid phone number!");
                            }}
                        }}

                        document.getElementById('phone_input').addEventListener('keypress', function (e) {{
                            if (e.key === 'Enter') {{
                                openWA();
                            }}
                        }});
                        </script>
                        </body>
                        </html>
                        """
                        
                        components.html(html_code, height=55)
                        
                    st.divider()
                    #  WhatsApp Alert Section End 

                    
                    
                    
elif st.session_state.view == "cpu":
    st.subheader("🔥 CPU Usage (SOC View)")

    hosts = cached_hosts()
    grouped = group_hosts(hosts)

    for gname in sorted(grouped.keys()):
        with st.expander(f"📁 {gname} — {len(grouped[gname])} hosts", expanded=(gname in ("Core", "Firewall", "ISP"))):
            for h in grouped[gname]:
                ip = get_host_ip(h["hostid"])
                cpu = cached_cpu(h["hostid"])
                if cpu is None:
                    continue

                st.markdown(
                    f"""
### 🖥️ {h['name']} ({ip})
- **CPU Usage:** {cpu:.1f} %
- **Status:** {cpu_status(cpu)}
"""
                )

elif st.session_state.view == "memory":
    st.subheader("🧠 Memory Usage (SOC View)")

    hosts = cached_hosts()
    grouped = group_hosts(hosts)

    for gname in sorted(grouped.keys()):
        with st.expander(f"📁 {gname} — {len(grouped[gname])} hosts", expanded=(gname in ("Core", "Firewall", "ISP"))):
            for h in grouped[gname]:
                ip = get_host_ip(h["hostid"])
                mem = cached_memory(h["hostid"])
                if mem is None:
                    continue

                st.markdown(
                    f"""
### 🖥️ {h['name']} ({ip})
- **Memory Usage:** {mem:.1f} %
- **Status:** {memory_status(mem)}
"""
                )

elif st.session_state.view == "bandwidth":
    WINDOWS = {"5 minute": 300, "1 hour": 3600}

    if "bw_window_sec" not in st.session_state:
        st.session_state.bw_window_sec = 300

    choice = st.radio(
        "Bandwidth Time Window",
        options=list(WINDOWS.keys()),
        index=0 if st.session_state.bw_window_sec == 300 else 1,
        horizontal=True,
        key="bw_window_choice"
    )

    window_sec = WINDOWS[choice]
    st.session_state.bw_window_sec = window_sec

    st.subheader("🌐 Bandwidth Usage (Grouped SOC View)")

    hosts = cached_hosts()
    max_hosts = st.slider("Hosts to load", 5, 200, 50)
    hosts = hosts[:max_hosts]

    grouped = group_hosts(hosts)

    for gname in sorted(grouped.keys()):
        with st.expander(f"📁 {gname} — {len(grouped[gname])} hosts", expanded=(gname in ("Core", "Firewall", "ISP"))):
            for idx, h in enumerate(grouped[gname], start=1):
                hostid = h["hostid"]
                ip = get_host_ip(hostid)

                cpu = cached_cpu(hostid)
                mem = cached_memory(hostid)
                probs = cached_problems_by_host(hostid) or []

                bw = cached_bandwidth(hostid, window_sec=window_sec)
                if bw is None:
                    bw = {
                        "in_avg": 0.0, "out_avg": 0.0, "total_avg": 0.0,
                        "in_inst": 0.0, "out_inst": 0.0, "total_inst": 0.0,
                        "time": "Collecting..."
                    }

                incoming_avg = float(bw.get("in_avg") or 0.0)
                outgoing_avg = float(bw.get("out_avg") or 0.0)
                total_avg = float(bw.get("total_avg") or (incoming_avg + outgoing_avg))

                incoming_inst = float(bw.get("in_inst") or 0.0)
                outgoing_inst = float(bw.get("out_inst") or 0.0)
                total_inst = float(bw.get("total_inst") or (incoming_inst + outgoing_inst))

                time_bd = bw.get("time") or "Collecting..."

                if total_avg < 150:
                    status = "🟢 Normal"
                elif total_avg < 3000:
                    status = "🟠 High"
                else:
                    status = "🔴 Critical"

                bw_ai = {"in": incoming_avg, "out": outgoing_avg, "total": total_avg, "time": time_bd}

                st.markdown(f"### 🖥️ {h['name']} ({ip})")
                c1m, c2m, c3m, c4m, c5m = st.columns(5)
                c1m.metric("CPU %", "-" if cpu is None else f"{cpu:.1f}")
                c2m.metric("Memory %", "-" if mem is None else f"{mem:.1f}")
                c3m.metric("BW Mbps (avg)", f"{total_avg:.2f}")
                c4m.metric("Problems", str(len(probs)))
                c5m.metric("Status", status)

                st.write(f"- **Time:** `{time_bd}`")
                st.write(f"- **Incoming:** {incoming_avg:.2f} Mbps (avg) | {incoming_inst:.2f} Mbps (instant)")
                st.write(f"- **Outgoing:** {outgoing_avg:.2f} Mbps (avg) | {outgoing_inst:.2f} Mbps (instant)")
                st.write(f"- **Total:** {total_avg:.2f} Mbps (avg) | {total_inst:.2f} Mbps (instant)")

                if probs:
                    with st.expander("🚨 Active Problems", expanded=False):
                        for p in probs[:10]:
                            st.write(f"🔴 Sev {p.get('severity','?')} — {p.get('name','N/A')}")

                if total_avg >= 200:
                    if st.button("🧠 Explain Bandwidth Issue", key=f"bw_ai_{gname}_{hostid}_{idx}"):
                        with st.spinner("AI analyzing bandwidth traffic..."):
                            st.session_state.ai_result = mistral_explain_bandwidth(h["name"], ip, bw_ai)
                        st.session_state.view = "ai"
                        st.rerun()

                st.divider()

elif st.session_state.view == "ai":
    st.subheader("🧠 AI Explanation (SOC Style)")
    st.success(st.session_state.ai_result)

else:
    st.info("Type a command above, or use Quick Actions to get started.")
