"""One command: bring the lab up, scan it, tear it down.

    python lab/lab.py

Runs on the host. Everything it does is ``docker compose``, so there is nothing
to install beyond Docker itself, and the teardown happens whether the run
succeeded, failed or was interrupted.

    python lab/lab.py --keep            leave the containers running
    python lab/lab.py --only <id>,<id>  run named scenarios only
    python lab/lab.py --down            tear down and exit

The exit code is the runner's: non-zero when a declared finding was not
produced, or when something was reported that nothing declared.
"""

import argparse
import os
import shutil
import subprocess
import sys

LAB = os.path.dirname(os.path.abspath(__file__))
COMPOSE_FILE = os.path.join(LAB, "docker-compose.yml")


def compose(*arguments, **kwargs):
    """Run one docker compose command against this lab's file."""
    command = ["docker", "compose", "-f", COMPOSE_FILE] + list(arguments)
    print("[lab] " + " ".join(command))
    return subprocess.call(command, **kwargs)


def engine_is_up():
    """Whether the Docker engine answers at all."""
    if shutil.which("docker") is None:
        print("[lab] docker is not on PATH.")
        return False
    probe = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if probe.returncode != 0:
        print("[lab] the Docker engine is not answering. Start Docker and "
              "run this again.")
        print("[lab] " + probe.stderr.decode("utf-8", "replace").strip()[:300])
        return False
    print("[lab] Docker engine %s"
          % probe.stdout.decode("utf-8", "replace").strip())
    return True


def teardown():
    # Volumes and orphans included: the lab keeps nothing between runs, so a
    # cache cannot carry a stored response from one run into the next.
    compose("down", "--volumes", "--remove-orphans")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--keep", action="store_true",
                        help="leave the containers running after the scan")
    parser.add_argument("--only",
                        help="comma-separated scenario ids to run")
    parser.add_argument("--down", action="store_true",
                        help="tear the lab down and exit")
    parser.add_argument("--build", action="store_true",
                        help="rebuild the runner image before scanning")
    arguments = parser.parse_args()

    if not engine_is_up():
        return 2
    if arguments.down:
        teardown()
        return 0

    out = os.path.join(LAB, "out")
    if not os.path.isdir(out):
        os.makedirs(out)

    environment = dict(os.environ)
    if arguments.only:
        environment["LAB_ONLY"] = arguments.only

    try:
        up = ["up", "--detach", "--wait"]
        if arguments.build:
            up.append("--build")
        if compose(*up) != 0:
            print("[lab] the services did not come up.")
            compose("logs", "--tail", "40")
            return 2
        code = compose("run", "--rm", "--no-deps", "runner", env=environment)
        # The container writes into lab/out, which is not kept. The report is
        # a deliverable, so a full run leaves a copy beside the scenarios.
        produced = os.path.join(out, "report.md")
        if os.path.isfile(produced) and not arguments.only:
            shutil.copyfile(produced, os.path.join(LAB, "report.md"))
            print("[lab] report copied to lab/report.md")
    except KeyboardInterrupt:
        print("\n[lab] interrupted")
        code = 130
    finally:
        if arguments.keep:
            print("[lab] left running; tear it down with "
                  "'python lab/lab.py --down'")
        else:
            teardown()
    return code


if __name__ == "__main__":
    sys.exit(main())
