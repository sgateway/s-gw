#!/usr/bin/env python3
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
HARNESS = r'''
#define SGW_CENSUS_TEST 1
#include "agent-census.c"

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    if (strcmp(argv[1], "mount") == 0) {
        const char *allowed[] = { "/" };
        unsigned char seen[1] = { 0 };
        return mount_line_ok(argv[2], allowed, 1, seen) && seen[0] ? 0 : 1;
    }
    if (strcmp(argv[1], "stat") == 0) {
        unsigned long long starttime = 0;
        return proc_stat_starttime(argv[2], &starttime) && starttime == 1234 ? 0 : 1;
    }
    if (strcmp(argv[1], "uid-all") == 0 || strcmp(argv[1], "uid-any") == 0) {
        unsigned long long uids[4] = { 0 };
        if (!parse_status_uids(argv[2], uids)) return 1;
        int hit = strcmp(argv[1], "uid-all") == 0 ? uids_all(uids, 1001) : uids_any(uids, 1001);
        return hit ? 0 : 1;
    }
    if (strcmp(argv[1], "walk") == 0) {
        int root = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        struct stat null_info;
        size_t entries = 0;
        if (root < 0 || stat("/dev/null", &null_info) != 0) return 2;
        int okay = scan_tree(root, null_info.st_rdev, &entries, 0);
        close(root);
        return okay ? 0 : 1;
    }
    if (strcmp(argv[1], "scan-uids") == 0) {
        int proc_root = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (proc_root < 0) return 2;
        int okay = scan_other_uids_at(proc_root, 99, 1001);
        close(proc_root);
        return okay ? 0 : 1;
    }
    return 2;
}
'''


class CensusParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_dir = tempfile.TemporaryDirectory(prefix="sgw-census-test-")
        source = Path(cls.build_dir.name) / "harness.c"
        source.write_text(HARNESS)
        cls.binary = Path(cls.build_dir.name) / "census-test"
        result = subprocess.run([
            "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
            "-DSGW_CENSUS_MAX_ENTRIES=32", "-DSGW_CENSUS_MAX_PROC_PIDS=32",
            "-DSGW_CENSUS_MAX_PROC_TIDS=32",
            "-I", str(HERE), str(source),
            "-o", str(cls.binary),
        ], capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.build_dir.cleanup()

    def check(self, kind, value, expected):
        result = subprocess.run([str(self.binary), kind, str(value)], capture_output=True)
        self.assertEqual(result.returncode, expected, result.stderr.decode())

    def test_private_root_mount(self):
        self.check("mount", "36 25 0:32 / / rw,relatime - ext4 /dev/sda rw", 0)

    def test_shared_mount_rejected(self):
        self.check("mount", "36 25 0:32 / / rw shared:5 - ext4 /dev/sda rw", 1)

    def test_master_mount_rejected(self):
        self.check("mount", "36 25 0:32 / / rw master:5 - ext4 /dev/sda rw", 1)

    def test_propagate_from_mount_rejected(self):
        self.check("mount", "36 25 0:32 / / rw propagate_from:5 - ext4 /dev/sda rw", 1)

    def test_extra_mount_rejected(self):
        self.check("mount", "37 25 0:33 / /run/broker rw - tmpfs tmpfs rw", 1)

    def test_malformed_mount_rejected(self):
        self.check("mount", "36 25 0:32 / / rw - ext4", 1)

    def test_proc_stat_handles_spaces_and_parentheses(self):
        fields = ["S"] + ["1"] * 18 + ["1234"] + ["0"] * 30
        self.check("stat", "123 (odd ) command) " + " ".join(fields), 0)

    def test_proc_stat_rejects_missing_fields(self):
        self.check("stat", "123 (process) S 1 2 3", 1)

    def test_target_requires_all_four_dedicated_uids(self):
        self.check("uid-all", "Name:\tgate\nUid:\t1001\t1001\t1001\t1001\nGid:\t1002\t1002\t1002\t1002\n", 0)
        self.check("uid-all", "Name:\tgate\nUid:\t1001\t1001\t0\t1001\n", 1)

    def test_other_process_collision_checks_every_uid(self):
        self.check("uid-any", "Uid:\t0\t0\t1001\t0\n", 0)
        self.check("uid-any", "Uid:\t0\t0\t0\t1001\n", 0)
        self.check("uid-any", "Uid:\t0\t0\t0\t0\n", 1)

    def test_uid_line_must_be_complete_and_unique(self):
        self.check("uid-all", "Uid:\t1001\t1001\t1001\n", 1)
        self.check("uid-all", "Uid:\t1001\t1001\t1001\t1001\t0\n", 1)
        self.check("uid-all", "Name:\tgate\n", 1)
        self.check("uid-all", "Uid:\t1001\t1001\t1001\t1001\nUid:\t1001\t1001\t1001\t1001\n", 1)

    def test_global_scan_rejects_saved_uid_collision(self):
        with tempfile.TemporaryDirectory(prefix="sgw-census-proc-") as root:
            self.fake_status(root, 99, "1001\t1001\t1001\t1001")
            self.fake_status(root, 123, "0\t0\t0\t0")
            self.check("scan-uids", root, 0)
            self.fake_status(root, 123, "0\t0\t1001\t0")
            self.check("scan-uids", root, 1)

    def test_global_scan_rejects_malformed_status(self):
        with tempfile.TemporaryDirectory(prefix="sgw-census-proc-") as root:
            self.fake_status(root, 123, "broken")
            self.check("scan-uids", root, 1)

    def test_global_scan_rejects_thread_uid_collision(self):
        with tempfile.TemporaryDirectory(prefix="sgw-census-proc-") as root:
            self.fake_status(root, 123, "0\t0\t0\t0")
            thread = Path(root) / "123" / "task" / "124"
            thread.mkdir()
            (thread / "status").write_text("Name:\tworker\nUid:\t0\t0\t0\t1001\n")
            self.check("scan-uids", root, 1)

    def test_global_scan_rejects_missing_task_directory(self):
        with tempfile.TemporaryDirectory(prefix="sgw-census-proc-") as root:
            self.fake_status(root, 123, "0\t0\t0\t0")
            shutil.rmtree(Path(root) / "123" / "task")
            self.check("scan-uids", root, 1)

    def test_global_scan_limit_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="sgw-census-proc-") as root:
            for number in range(100, 133):
                self.fake_status(root, number, "0\t0\t0\t0")
            self.check("scan-uids", root, 1)

    @staticmethod
    def fake_status(root, pid, ids):
        directory = Path(root) / str(pid)
        directory.mkdir(exist_ok=True)
        status = "Name:\tfixture\nUid:\t" + ids + "\n"
        (directory / "status").write_text(status)
        task = directory / "task" / str(pid)
        task.mkdir(parents=True, exist_ok=True)
        (task / "status").write_text(status)

    def test_regular_files_and_directories(self):
        with tempfile.TemporaryDirectory(prefix="sgw-census-root-") as root:
            os.mkdir(Path(root) / "bin")
            (Path(root) / "bin" / "agent").write_bytes(b"agent")
            self.check("walk", root, 0)

    def test_socket_alias_rejected(self):
        with tempfile.TemporaryDirectory(prefix="sgw-census-root-") as root:
            alias = Path(root) / "broker.sock"
            sock = socket.socket(socket.AF_UNIX)
            try:
                sock.bind(str(alias))
                self.check("walk", root, 1)
            finally:
                sock.close()

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory(prefix="sgw-census-root-") as root:
            (Path(root) / "escape").symlink_to("/proc/self/fd")
            self.check("walk", root, 1)

    def test_fifo_rejected(self):
        with tempfile.TemporaryDirectory(prefix="sgw-census-root-") as root:
            os.mkfifo(Path(root) / "pipe")
            self.check("walk", root, 1)

    def test_walk_limit_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="sgw-census-root-") as root:
            for number in range(33):
                (Path(root) / str(number)).touch()
            self.check("walk", root, 1)


if __name__ == "__main__":
    unittest.main()
