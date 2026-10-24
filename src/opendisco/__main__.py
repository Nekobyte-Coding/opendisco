"""`python -m opendisco` opens the GUI; with command-line options it runs the CLI instead."""
import sys

# macOS can add a -psn_0_<number> argument when Finder opens an app (a first launch after Gatekeeper,
# say): that's not a request for the command line.
sys.argv[1:] = [arg for arg in sys.argv[1:] if not arg.startswith("-psn_")]
if len(sys.argv) > 1:
    from opendisco.core import main as cli_main

    sys.exit(cli_main())
else:
    from opendisco.app import main

    main().main_loop()
