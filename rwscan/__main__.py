"""python -m rwscan 的命令行入口。"""

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

from .config import load_config
from .listing import Room, aggregate, exclusion_reason, fetch_rooms, now, resolve_hosts, resolve_room_addresses
from .scanner import scan_rooms
from .storage import write_json


def display(value):
    return "".join(c if c.isprintable() else " " for c in str(value))[:200]


def status_label(status):
    # 只翻译终端展示，持久化状态仍保留稳定的协议/扫描标识。
    labels = {
        "connecting": "正在连接",
        "lookup_failed": "地址查询失败",
        "connection_failed": "连接失败",
        "no_server_info": "未收到服务器预注册响应",
        "registered_unconfirmed": "已注册，等待加入确认",
        "listening": "正在监听",
        "listened": "监听结束",
        "redirected": "已跳转",
        "redirect_failed": "跳转失败",
        "redirect_loop": "跳转循环",
        "kicked": "被服务器踢出",
        "disconnected": "服务器已断开连接",
        "connection_closed": "连接已关闭",
        "join_rejected": "加入被拒绝",
        "password_required": "需要密码或密码错误",
        "protocol_error": "协议错误",
        "excluded": "已排除",
        "battleroom": "等待玩家",
        "ingame": "游戏进行中",
        "locked": "房间已锁定",
    }
    return labels.get(status, f"未知状态（{display(status)}）")


def output_inventory(rooms, report, config):
    root = Path(config.output_dir)
    report["get_queries"] = resolve_room_addresses(rooms, config)
    report["dns_errors"] = resolve_hosts(rooms)
    selected, excluded = [], []
    for room in rooms:
        reason = exclusion_reason(room, config)
        if reason:
            excluded.append({"reason": reason, "room": room.to_dict()})
        else:
            selected.append(room)
    grouped = aggregate(selected)
    inventory = {"fetched_at": now(), "rooms": [r.to_dict() for r in selected], "by_ip": grouped,
                 "excluded": excluded, "report": report}
    write_json(root / "rooms.json", inventory)
    write_json(root / "all_rooms.json", {"fetched_at": inventory["fetched_at"], "rooms": [r.to_dict() for r in rooms]})
    write_json(root / "fetch_report.json", report)
    fields = ["ip", "port", "room_id", "room_name", "map_name", "version", "version_code", "players",
              "max_players", "status", "password_required", "port_open", "mods", "dedicated", "lookup_code"]
    with (root / "rooms.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fields, extrasaction="ignore")
        writer.writeheader()
        for ip, ports in grouped.items():
            for port, items in ports.items():
                for room in items:
                    writer.writerow({**room, "ip": ip, "port": port})
    for ip, ports in grouped.items():
        print(display(ip))
        for port, items in ports.items():
            for room in items:
                players = "?" if room["players"] is None else room["players"]
                maximum = "?" if room["max_players"] is None else room["max_players"]
                print(f"  :{port}  {display(room['room_name'])} | {display(room['map_name'])} | "
                      f"{display(room['version'])} ({room['version_code']}) | "
                      f"{players}/{maximum} | {status_label(room['status'])}")
    failures = [q for q in report["queries"] if q["error"]]
    get_failures = [q for q in report["get_queries"] if q["status"] == "failed"]
    print(f"共取得 {len(rooms)} 个房间记录，纳入 {len(selected)} 个，排除 {len(excluded)} 个，聚合 {len(grouped)} 个 IP/域名。")
    if failures:
        print(f"{len(failures)} 次查询失败，详情见 fetch_report.json。", file=sys.stderr)
    if report["parse_errors"]:
        print(f"{len(report['parse_errors'])} 行解析失败，原文已保存。", file=sys.stderr)
    if get_failures:
        print(f"{len(get_failures)} 个房间 get 失败，记录已保留，未参与 IP 聚合，详情见 fetch_report.json。", file=sys.stderr)
    return selected, bool(failures or get_failures or report["parse_errors"] or report["dns_errors"])


def main(argv=None):
    parser = argparse.ArgumentParser(description="gs1/gs4 房间聚合与 1.15 聊天关键词扫描器（Python 标准库）")
    subcommands = parser.add_subparsers(dest="command", required=True)
    for command, help_text in [("list", "获取公开列表并按 IP/端口聚合"), ("scan", "获取列表后加入房间监听关键词")]:
        subparser = subcommands.add_parser(command, help=help_text)
        subparser.add_argument("--config", metavar="JSON", help="JSON 配置文件，不指定时使用默认值")
        subparser.add_argument("--output", metavar="DIR", help="覆盖结果目录")
        subparser.add_argument("--version", action="append", type=int, help="覆盖列表查询版本，可重复；同时保留无版本查询")
        subparser.add_argument("--include-dedicated", action="store_true", help="将列表 dedicated=true 的官方/专用记录也纳入")
        if command == "scan":
            subparser.add_argument("--rooms-file", metavar="JSON", help="使用 rooms.json/all_rooms.json，跳过列表获取")
            subparser.add_argument("--room-id", action="append", help="只扫描指定房间 ID，可重复")
            subparser.add_argument("--limit", type=int, help="本次最多扫描多少个房间")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.output:
            config.output_dir = args.output
        if args.version:
            config.list_versions = [None, *args.version]
        if args.include_dedicated:
            config.exclude_dedicated = False
        config.validate()
        if args.command == "scan" and not config.keywords:
            raise ValueError("scan 需要在配置 keywords 中指定至少一个关键词")
        if args.command == "scan" and args.limit is not None and args.limit < 1:
            raise ValueError("--limit 必须是正整数")
        partial = False
        if args.command == "scan" and args.rooms_file:
            data = json.loads(Path(args.rooms_file).read_text(encoding="utf-8-sig"))
            rooms = [Room.from_dict(r) for r in data["rooms"]]
            rooms = [r for r in rooms if exclusion_reason(r, config) is None]
        else:
            rooms, report = fetch_rooms(config, Path(config.output_dir) / "raw")
            rooms, partial = output_inventory(rooms, report, config)
            if not any(q["error"] is None for q in report["queries"]):
                print("全部列表查询失败。", file=sys.stderr)
                return 1
        if args.command == "list":
            return 2 if partial else 0
        if args.room_id:
            requested = set(args.room_id)
            found = {r.room_id for r in rooms}
            if requested - found:
                raise ValueError("找不到指定房间 ID：" + ", ".join(sorted(requested - found)))
            rooms = [r for r in rooms if r.room_id in requested]
        if args.limit is not None:
            rooms = rooms[:args.limit]
        if not rooms:
            print("没有可扫描的房间。", file=sys.stderr)
            return 1
        print(f"开始监听 {len(rooms)} 个房间，每个最多 {config.listen_seconds:g} 秒，并发 {config.concurrency}。")

        def show_result(result):
            room = result["room"]
            print(f"{display(room['host'])}:{room['port']} {display(room['room_name'])} "
                  f"状态={status_label(result['status'])} 聊天={result['chat_count']} 命中={len(result['matches'])} 跳转={len(result['redirects'])}", flush=True)

        results = scan_rooms(rooms, config, show_result)
        counts = Counter(r["status"] for r in results)
        print("扫描状态：" + "，".join(f"{status_label(k)}={v}" for k, v in sorted(counts.items())))
        print(f"结果目录：{config.output_dir}；命中服务器见 matched_servers.json，跳转见 redirects.jsonl。")
        successful = {"listened", "disconnected", "connection_closed", "excluded"}
        failed = any(r["status"] not in successful or
                     (r["status"] != "excluded" and not any(e.get("connected") for e in r["endpoints"])) for r in results)
        return 2 if partial or failed else 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("错误：" + display(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("扫描被中断；已落盘的结果保留。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
