import subprocess
import sys
from pathlib import Path

SERVICE_NAME = "warpper.service"
SERVICE_PATH = Path("/etc/systemd/system") / SERVICE_NAME
SCRIPT_PATH = Path(__file__).resolve()


UNIT = f"""\
[Unit]
Description=Warpper
After=network.target

[Service]
Type=exec
ExecStart={sys.executable} {SCRIPT_PATH}
Restart=on-failure
RestartSec=2

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

StandardOutput=journal
StandardError=journal
SyslogIdentifier=dnsproxy

[Install]
WantedBy=multi-user.target
"""


def install_service():
    if hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() != 0:
        print("Run this installer as root:")
        print(f"sudo {sys.executable} {SCRIPT_PATH}")
        sys.exit(1)

    SERVICE_PATH.write_text(UNIT)

    subprocess.run(
        ["systemctl", "daemon-reload"],
        check=True,
    )

    subprocess.run(
        ["systemctl", "enable", "--now", SERVICE_NAME],
        check=True,
    )

    print(f"Installed and started {SERVICE_NAME}")


if __name__ == "__main__":
    install_service()
