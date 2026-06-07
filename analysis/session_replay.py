import json
from collections import defaultdict

sessions = defaultdict(list)
log_path = r"..\honeypot\sample-logs\all-cowrie-logs.json\all-cowrie-logs.json"

with open(log_path) as f:
    for line in f:
        try:
            event = json.loads(line)
            if event.get("eventid") == "cowrie.command.input":
                sessions[event.get("session")].append({
                    "time": event.get("timestamp"),
                    "cmd": event.get("input"),
                    "ip": event.get("src_ip")
                })
        except:
            pass

top = sorted(sessions.items(), key=lambda x: len(x[1]), reverse=True)[:5]
for sid, cmds in top:
    print(f"Session: {sid} | IP: {cmds[0]['ip']} | Commands: {len(cmds)}")
    for c in cmds:
        print(f"  {c['time']} -> {c['cmd']}")
    print()
