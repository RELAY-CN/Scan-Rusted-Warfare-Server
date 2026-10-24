"""保存扫描会话，并按端点图归并跳转前后的服务器。"""

import hashlib
import json
import os
import threading
import uuid
from pathlib import Path

from .listing import now
from .transport import authority


def write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    # 转义孤立 surrogate，避免恶意 UTF 字符串破坏 UTF-8 输出。
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, ensure_ascii=True, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def endpoint_nodes(endpoint):
    return [authority(ip, endpoint["port"]) for ip in endpoint.get("ips", []) or [endpoint["host"]]]


class Store:
    def __init__(self, output_dir, save_all_chat=False):
        self.root = Path(output_dir)
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.save_all_chat = save_all_chat
        path = self.root / "sessions.json"
        self.sessions = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        if not isinstance(self.sessions, dict):
            raise ValueError("sessions.json 必须是对象")

    def begin(self, room, proxy_index):
        session_id = str(uuid.uuid4())
        with self.lock:
            self.sessions[session_id] = {"session_id": session_id, "started_at": now(), "room": room.to_dict(),
                                         "proxy_index": proxy_index, "endpoints": [], "redirects": [],
                                         "matches": [], "status": "connecting", "errors": [], "chat_count": 0}
            self._flush()
        return session_id

    def endpoint(self, session_id, endpoint):
        with self.lock:
            current = self.sessions[session_id]
            previous = next((x for x in current["endpoints"] if (x["host"], x["port"], x.get("query")) ==
                             (endpoint["host"], endpoint["port"], endpoint.get("query"))), None)
            if previous:
                previous.update(endpoint)
            else:
                current["endpoints"].append(endpoint)
            self._flush()

    def redirect(self, session_id, redirect):
        with self.lock:
            self.sessions[session_id]["redirects"].append({"at": now(), **redirect})
            self._append("redirects.jsonl", {"session_id": session_id, **redirect, "at": now()})
            self._flush()

    def metadata(self, session_id, key, value):
        with self.lock:
            self.sessions[session_id][key] = value
            self._flush()

    def chat(self, session_id, endpoint, chat, keywords):
        with self.lock:
            session = self.sessions[session_id]
            session["chat_count"] += 1
            event = {"session_id": session_id, "at": now(), "endpoint": endpoint,
                     "room_id": session["room"]["room_id"], **chat}
            if self.save_all_chat:
                self._append("chat.jsonl", event)
            if keywords:
                event["keywords"] = keywords
                session["matches"].append(event)
                self._append("matches.jsonl", event)
                self._flush()

    def error(self, session_id, message):
        with self.lock:
            self.sessions[session_id]["errors"].append({"at": now(), "error": message})
            self._flush()

    def finish(self, session_id, status):
        with self.lock:
            self.sessions[session_id].update(status=status, finished_at=now())
            self._flush()

    def _append(self, filename, event):
        with (self.root / filename).open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(event, ensure_ascii=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def _flush(self):
        write_json(self.root / "sessions.json", self.sessions)
        write_json(self.root / "matched_servers.json", self._groups())

    def _groups(self):
        parents = {}

        def find(node):
            parents.setdefault(node, node)
            if parents[node] != node:
                parents[node] = find(parents[node])
            return parents[node]

        session_nodes = {}
        for key, session in self.sessions.items():
            nodes = {n for endpoint in session["endpoints"] for n in endpoint_nodes(endpoint)}
            session_nodes[key] = nodes
            if nodes:
                root = find(sorted(nodes)[0])
                for node in nodes:
                    parents[find(node)] = root
        groups = {}
        for key, session in self.sessions.items():
            nodes = session_nodes[key]
            if not nodes:
                continue
            root = find(sorted(nodes)[0])
            group = groups.setdefault(root, {"endpoints": {}, "rooms": [], "matches": [], "redirected": False, "session_ids": []})
            for endpoint in session["endpoints"]:
                identity = (endpoint["host"], endpoint["port"], endpoint.get("query"))
                old = group["endpoints"].get(identity)
                if old:
                    connected = old.get("connected", False) or endpoint.get("connected", False)
                    old.update(endpoint)
                    old["connected"] = connected
                else:
                    group["endpoints"][identity] = endpoint.copy()
            room = {**session["room"], "redirected": bool(session["redirects"]), "observed_map": session.get("observed_map")}
            if room not in group["rooms"]:
                group["rooms"].append(room)
            group["matches"].extend(session["matches"])
            group["redirected"] |= bool(session["redirects"])
            group["session_ids"].append(key)
        result = []
        for group in groups.values():
            if not group["matches"]:
                continue
            group["endpoints"] = list(group["endpoints"].values())
            nodes = sorted({n for ep in group["endpoints"] for n in endpoint_nodes(ep)})
            group["server_id"] = hashlib.sha256("|".join(nodes).encode()).hexdigest()[:16]
            group["ip_ports"] = nodes
            result.append(group)
        return result
