import ipaddress
import os
import shutil
import subprocess


class FirewallError(Exception):
    pass


class Firewall:
    def __init__(
        self,
        nft_family,
        nft_table,
        block_set,
        port,
        daemon_uid=None,
        logger=None,
    ):
        self.family = nft_family
        self.table = nft_table
        self.block_set = block_set
        self.block_set6 = f"{block_set}6"
        self.port = port
        self.daemon_uid = os.getuid() if daemon_uid is None else daemon_uid
        self.logger = logger

        self.enabled = False

    def apply(self):
        if self.enabled:
            return

        self._require_nft()

        try:
            self._create_table()
            self._create_block_sets()
            self._create_redirect_chain()
            self._create_forward_chain()
            # self._create_output_drop_chain()
        except FirewallError:
            try:
                self._delete_table()
            except Exception:  # noqa: BLE001
                if self.logger:
                    self.logger.debug(
                        "rollback: failed to delete table.", exe_info=True
                    )
            raise

        self.enabled = True

        if self.logger:
            self.logger.info(
                "firewall enabled (table %s %s, daemon uid %s)",
                self.family,
                self.table,
                self.daemon_uid,
            )

    def remove(self):
        if not self.enabled and not self._table_exists():
            return

        self._delete_table()
        self.enabled = False

        if self.logger:
            self.logger.info("firewall disabled")

    def is_applied(self):
        return self._table_exists()

    def observe(self, client_ip, qname, ips):
        if not self.enabled or not ips:
            return

        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                if self.logger:
                    self.logger.warning(
                        "ignoring invalid resolved IP %r for %s",
                        ip,
                        qname,
                    )
                continue

            target_set = self.block_set6 if addr.version == 6 else self.block_set

            try:
                self._add_to_block_set(target_set, addr)

                if self.logger:
                    self.logger.info(
                        "blocked IP %s from %s (%s)",
                        addr,
                        qname,
                        client_ip,
                    )

            except FirewallError as exc:
                if self.logger:
                    self.logger.warning(
                        "block-set add failed for %s: %s",
                        ip,
                        exc,
                    )

    def _require_nft(self):
        if shutil.which("nft") is None:
            raise FirewallError("nft not found on PATH")

    def _run(self, *args, check=True):
        cmd = ["nft", *args]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )

        if check and result.returncode != 0:
            stderr = result.stderr.strip()

            raise FirewallError(f"{' '.join(cmd)}: {stderr or 'unknown nft error'}")

        return result

    def _table_exists(self):
        result = self._run(
            "list",
            "table",
            self.family,
            self.table,
            check=False,
        )

        return result.returncode == 0

    def _create_table(self):
        self._run(
            "add",
            "table",
            self.family,
            self.table,
        )

    def _delete_table(self):
        self._run(
            "delete",
            "table",
            self.family,
            self.table,
            check=False,
        )

    def _create_block_sets(self):
        self._run(
            "add",
            "set",
            self.family,
            self.table,
            self.block_set,
            "{ type ipv4_addr; flags timeout; }",
        )

        self._run(
            "add",
            "set",
            self.family,
            self.table,
            self.block_set6,
            "{ type ipv6_addr; flags timeout; }",
        )

    def _add_to_block_set(self, set_name, addr):
        self._run(
            "add",
            "element",
            self.family,
            self.table,
            set_name,
            "{",
            str(addr),
            "timeout",
            "300s",
            "}",
        )

    def _create_redirect_chain(self):
        chain = "dns_out"

        self._run(
            "add",
            "chain",
            self.family,
            self.table,
            chain,
            "{ type nat hook output priority dstnat; policy accept; }",
        )

        self._run(
            "add",
            "rule",
            self.family,
            self.table,
            chain,
            "meta",
            "skuid",
            str(self.daemon_uid),
            "counter",
            "return",
        )

        self._run(
            "add",
            "rule",
            self.family,
            self.table,
            chain,
            "udp",
            "dport",
            "53",
            "counter",
            "redirect",
            "to",
            f":{self.port}",
        )

        self._run(
            "add",
            "rule",
            self.family,
            self.table,
            chain,
            "tcp",
            "dport",
            "53",
            "counter",
            "redirect",
            "to",
            f":{self.port}",
        )

    def _create_forward_chain(self):
        chain = "forward"

        self._run(
            "add",
            "chain",
            self.family,
            self.table,
            chain,
            "{ type filter hook forward priority filter; policy accept; }",
        )

        self._run(
            "add",
            "rule",
            self.family,
            self.table,
            chain,
            "ip",
            "daddr",
            f"@{self.block_set}",
            "counter",
            "drop",
        )

        self._run(
            "add",
            "rule",
            self.family,
            self.table,
            chain,
            "ip6",
            "daddr",
            f"@{self.block_set6}",
            "counter",
            "drop",
        )

    def _create_output_drop_chain(self):
        chain = "drop_out"
        self._run(
            "add",
            "chain",
            self.family,
            self.table,
            chain,
            "{ type filter hook output priority filter; policy accept; }",
        )
        self._run(
            "add",
            "rule",
            self.family,
            self.table,
            chain,
            "meta",
            "skuid",
            str(self.daemon_uid),
            "return",
        )
        self._run(
            "add",
            "rule",
            self.family,
            self.table,
            chain,
            "ip",
            "daddr",
            f"@{self.block_set}",
            "counter",
            "drop",
        )
        self._run(
            "add",
            "rule",
            self.family,
            self.table,
            chain,
            "ip6",
            "daddr",
            f"@{self.block_set6}",
            "counter",
            "drop",
        )
