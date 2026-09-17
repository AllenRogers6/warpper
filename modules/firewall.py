import socket
import subprocess

from modules.rule_engine import RuleEngine


class FirewallManager:
    def __init__(self, db_path, nft_table, block_set, logger):
        self.rule_engine = RuleEngine(db_path)
        self.table = nft_table
        self.set = block_set
        self.set_name = f"{nft_table} {block_set}"
        self.logger = logger

    def setup_nftables(self):
        commands = [
            f"add table {self.table}",
            f"add chain {self.table} output {{ type filter hook output priority 0; policy accept; }}",
            f"add set {self.table} {self.set} {{ type ipv4_addr; flags interval; }}",
            f"add rule {self.table} output ip daddr @{self.set} drop",
        ]
        for cmd in commands:
            try:
                subprocess.run(["nft", *cmd.split()], check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                if b"File exists" not in e.stderr:
                    self.logger.error(f"nftables setup error: {e.stderr.decode()}")

    def update_blocked_ips(self):
        conn = self.rule_engine.db_conn
        domains = [
            row["pattern"]
            for row in conn.execute(
                "SELECT pattern FROM rules WHERE type='exact' AND action='block' AND enabled=1"
            ).fetchall()
        ]
        ips = set()
        for domain in domains:
            try:
                resolved = socket.gethostbyname_ex(domain)[2]
                for ip in resolved:
                    ips.add(ip)
            except socket.gaierror:
                pass
        subprocess.run(["nft", "flush", "set", self.table, self.set], check=True)
        for ip in ips:
            subprocess.run(
                ["nft", "add", "element", self.table, self.set, "{", ip, "}"],
                check=True,
            )
        self.logger.info(f"Updated firewall block set with {len(ips)} IPs.")
