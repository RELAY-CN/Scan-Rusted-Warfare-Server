"""兼容 python scan.py 的入口。"""

from rwscan.__main__ import main


if __name__ == "__main__":
    raise SystemExit(main())
