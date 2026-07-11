import sys

if len(sys.argv) > 1 and sys.argv[0].endswith("__main__.py"):
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
else:
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""

if cmd == "run":
    # Strip 'run' from argv so runner sees the right args
    sys.argv = [sys.argv[0]] + sys.argv[2:]
    from .runner import main
    main()
else:
    from .compiler import main
    main()
