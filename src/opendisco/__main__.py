"""`python -m opendisco` opens the GUI; with command-line options it runs the CLI instead."""
import sys

if len(sys.argv) > 1:
    from opendisco.core import main as cli_main

    sys.exit(cli_main())
else:
    from opendisco.app import main

    main().main_loop()
