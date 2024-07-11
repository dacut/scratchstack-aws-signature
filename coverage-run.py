#!/usr/bin/env python3
"""\
Usage: coverage-run.py [options] [<crates>]
Run coverage on specified crates in the workspace. If unspecified, all crates
in the workspace will be run.

Options:
    -h | --help
        Show this usage information.

    --clean | --no-clean
        Remove/do not remove build artifacts before running coverage tests. The
        default is to remove build artifacts.
    
    --test | --no-test
        Run tests/don't run tests. The default is to run tests.
    
    --report | --no-report
        Print/don't print a coverage reports. The default is to print reports.

    --html | --no-html
        Generate/don't generate HTML coverage reports. The default is to
        generate HTML reports.
    
    --open | --no-open
        Open the HTML coverage reports in the default browser. The default is
        to open the HTML coverage reports.
"""
from getopt import GetoptError, getopt
from os import O_DIRECTORY, O_RDONLY, environ, fwalk, makedirs
from os import open as os_open
from os import rmdir, scandir, unlink, walk
from os.path import abspath, dirname, exists
from os.path import join as path_join
from re import compile as re_compile
from re import escape
from subprocess import run
from sys import argv
from sys import exit as sys_exit
from sys import platform, stderr, stdout

import toml

ROOT = dirname(abspath(__file__))
ROOT_FD = os_open(ROOT, O_RDONLY | O_DIRECTORY)
ROOT_DIRS = []


def merge_env(**kwargs):
    env = dict(environ)
    env.update(kwargs)
    return env


class Crate:
    def __init__(self, root, cargodef):
        self.root = root
        self.cargodef = cargodef

    @property
    def crate_name(self):
        return self.cargodef["package"]["name"]

    @property
    def target_dir(self):
        return path_join(ROOT, "target", "coverage", self.crate_name)

    @property
    def profdata_filename(self):
        return path_join(self.target_dir, "cov.profdata")

    @property
    def html_dir(self):
        return path_join(ROOT, "coverage-html", self.crate_name)

    @property
    def target_exec(self):
        exec_name = re_compile(
            r"^" + escape(self.crate_name.replace("-", "_")) + r"-[0-9a-f]{16}$"
        )
        for entry in scandir(path_join(self.target_dir, "debug", "deps")):
            if not entry.is_file() or entry.stat().st_mode & 0o100 == 0:
                continue

            m = exec_name.match(entry.name)
            if m is not None:
                return entry.path

        raise RuntimeError(f"Could not find target executable for {self.crate_name}")

    @property
    def ignore_filename_regex(self):
        _ignore_filename_regex = getattr(self, "_ignore_filename_regex", None)
        if _ignore_filename_regex is None:
            self._ignore_filename_regex = (
                _ignore_filename_regex
            ) = self.get_ignore_filename_regex()

        return _ignore_filename_regex

    def get_ignore_filename_regex(self):
        entries = ["/.cargo", ".*thread/local.rs"]
        for entry in ROOT_DIRS:
            if not entry.is_dir():
                continue

            if entry.path.startswith(self.root):
                continue

            entries.append(escape(f"{entry.name}/"))

        return "|".join(entries)

    def clean(self):
        self.cargo("clean")

    def test(self):
        if exists(self.target_dir):
            for entry in scandir(self.target_dir):
                if entry.is_file() and (
                    entry.name.endswith(".profdata") or entry.name.endswith(".profraw")
                ):
                    unlink(entry.path)

        self.cargo("test")
        self.merge_profile_data()
        self.generate_lcov()

    def cargo(self, cmd, *args):
        args = ["cargo", cmd, "--target-dir", self.target_dir, *args]
        print("Running:", " ".join(args))
        self.run(args)

    def merge_profile_data(self):
        args = ["llvm-profdata", "merge", "-sparse"]
        for dirname, _, filenames in walk(self.target_dir):
            for filename in filenames:
                if filename.endswith(".profraw"):
                    args.append(path_join(dirname, filename))
        args.append("-o")
        args.append(self.profdata_filename)
        self.run(args)

    def generate_lcov(self):
        print(f"Generating {self.crate_name}.lcov file")
        args = [
            "llvm-cov",
            "export",
            "-format=lcov",
            f"-Xdemangler={environ['HOME']}/.cargo/bin/rustfilt",
            f"-ignore-filename-regex={self.ignore_filename_regex}",
            f"-instr-profile={self.profdata_filename}",
            path_join(self.target_dir, self.target_exec),
        ]
        with open(path_join(ROOT, f"{self.crate_name}.lcov"), "w") as fd:
            self.run(args, stdout=fd)

    def generate_html(self):
        makedirs(self.html_dir, exist_ok=True)
        for _, subdirs, filenames, dir_fd in fwalk(self.html_dir, topdown=False):
            for filename in filenames:
                unlink(filename, dir_fd=dir_fd)
            for subdir in subdirs:
                rmdir(subdir, dir_fd=dir_fd)
        args = [
            "llvm-cov",
            "show",
            "-format=html",
            f"-Xdemangler={environ['HOME']}/.cargo/bin/rustfilt",
            f"-ignore-filename-regex={self.ignore_filename_regex}",
            f"-instr-profile={self.profdata_filename}",
            f"-output-dir={self.html_dir}",
            path_join(self.target_dir, self.target_exec),
        ]

        result = self.run(args)

    def open_html(self):
        if platform == "darwin":
            self.run(["open", path_join(self.html_dir, "index.html")])
        elif platform == "linux":
            self.run(["xdg-open", path_join(self.html_dir, "index.html")])

    def generate_report(self):
        args = [
            "llvm-cov",
            "report",
            "-use-color",
            f"-Xdemangler={environ['HOME']}/.cargo/bin/rustfilt",
            f"-ignore-filename-regex={self.ignore_filename_regex}",
            f"-instr-profile={self.profdata_filename}",
            path_join(self.target_dir, self.target_exec),
        ]
        print("")
        print("Coverage report for", self.crate_name)
        self.run(args)

    def run(self, args, *, stdout=None):
        subproc_env = merge_env(
            LLVM_PROFILE_FILE=path_join(self.target_dir, "cov-%m.profraw")
        )
        run(args, cwd=self.root, check=True, env=subproc_env, stdout=stdout)


def load_workspace(members):
    results = []
    for member in members:
        crate_root = path_join(ROOT, member)
        path = path_join(crate_root, "Cargo.toml")
        with open(path, "r") as cargo_fd:
            cargo = toml.load(cargo_fd)
            results.append(Crate(crate_root, cargo))
    return results


def main(args):
    global ROOT_DIRS
    clean = True
    test = True
    html = True
    html_open = True
    report = True

    try:
        opts, args = getopt(
            args,
            "h",
            [
                "clean",
                "no-clean",
                "html",
                "no-html",
                "open",
                "no-open",
                "report",
                "no-report",
                "test",
                "no-test",
            ],
        )
        for opt, val in opts:
            if opt in ["-h", "--help"]:
                usage(stdout)
                return 0
            if opt in ["--clean"]:
                clean = True
            if opt in ["--no-clean"]:
                clean = False
            if opt in ["--html"]:
                html = True
            if opt in ["--no-html"]:
                html = False
            if opt in ["--open"]:
                html_open = True
            if opt in ["--no-open"]:
                html_open = False
            if opt in ["--report"]:
                report = True
            if opt in ["--no-report"]:
                report = False
            if opt in ["--test"]:
                test = True
            if opt in ["--no-test"]:
                test = False

    except GetoptError as e:
        print(e, file=stderr)
        usage()
        return 2

    for entry in scandir(ROOT):
        if entry.is_dir():
            ROOT_DIRS.append(entry)

    with open(path_join(ROOT, "Cargo.toml"), "r") as cargo_fd:
        cargo = toml.load(cargo_fd)

    if "workspace" in cargo:
        crates = load_workspace(cargo["workspace"]["members"])
    else:
        crates = [Crate(ROOT, cargo)]

    environ["CARGO_INCREMENTAL"] = "0"
    environ["RUSTFLAGS"] = "-Cinstrument-coverage -Ccodegen-units=1 -Copt-level=0"
    environ["RUST_LOG"] = "trace"

    if clean:
        for crate in crates:
            if not args or crate.crate_name in args:
                crate.clean()

    if test:
        for crate in crates:
            if not args or crate.crate_name in args:
                crate.test()

    if html:
        for crate in crates:
            if not args or crate.crate_name in args:
                crate.generate_html()

    if report:
        for crate in crates:
            if not args or crate.crate_name in args:
                crate.generate_report()

    if html and html_open:
        for crate in crates:
            if not args or crate.crate_name in args:
                crate.open_html()


def usage(fd=stderr):
    fd.write(__doc__)


if __name__ == "__main__":
    sys_exit(main(argv[1:]))
