"""Offline regressions for measurement helpers; no proxy or network required."""

import errno
import unittest
from unittest.mock import MagicMock, call, patch

import capacity_connections_probe as capacity
import connection_stability_check as stability


class ProbeHelperTests(unittest.TestCase):
    def test_proc_stats_require_a_complete_snapshot(self):
        self.assertFalse(stability.has_stats(stability.ProcStats(1, None, 1, 1)))
        self.assertTrue(stability.has_stats(stability.ProcStats(1, 2, 3, 4)))

    def test_fd_exhaustion_stops_idle_open_loop(self):
        for error_number in (errno.EMFILE, errno.ENFILE):
            with self.subTest(error_number=error_number):
                with patch.object(
                    stability.socket,
                    "create_connection",
                    side_effect=OSError(error_number, "file descriptor exhaustion"),
                ) as connect:
                    sockets, failed = stability.open_idle_connections(
                        "localhost", 1, 10_000, 1
                    )
                self.assertEqual(sockets, [])
                self.assertEqual(failed, 10_000)
                self.assertEqual(connect.call_count, 1)

    def test_churn_builds_a_fresh_payload_for_each_connection(self):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        payload_factory = MagicMock(side_effect=[b"first", b"second"])
        with patch.object(stability.socket, "create_connection", return_value=sock):
            ok, failed, _ = stability.run_churn(
                "localhost", 1, 2, 1, 1, payload_factory
            )
        self.assertEqual((ok, failed), (2, 0))
        self.assertEqual(payload_factory.call_count, 2)
        self.assertEqual(sock.sendall.call_args_list, [call(b"first"), call(b"second")])

    def test_realistic_tls_template_is_cached_by_hostname(self):
        capacity.build_realistic_client_hello.cache_clear()
        first = capacity.build_realistic_client_hello("example.com")
        self.assertIs(first, capacity.build_realistic_client_hello("example.com"))


if __name__ == "__main__":
    unittest.main()
