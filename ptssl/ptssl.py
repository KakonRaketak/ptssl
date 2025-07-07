#!/usr/bin/python3
"""
Copyright (c) 2025 Penterep Security s.r.o.

ptssl is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

ptssl is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ptssl.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import importlib
import os
import threading
import subprocess
import shutil
import tempfile
import json
import sys; sys.path.append(__file__.rsplit("/", 1)[0])

from io import StringIO
from types import ModuleType
from urllib.parse import urlparse, urlunparse

from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint, print_banner, help_print
from ptlibs.threads import ptthreads, printlock
from ptlibs.http.http_client import HttpClient

from helpers._thread_local_stdout import ThreadLocalStdout
from helpers.helpers import Helpers
from _version import __version__

import requests

class PtSSL:
    def __init__(self, args):
        self.ptjsonlib   = ptjsonlib.PtJsonLib()
        self.ptthreads   = ptthreads.PtThreads()
        self._lock       = threading.Lock()
        self.args        = args
        self.http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)
        self.helpers     = Helpers(args=self.args, ptjsonlib=self.ptjsonlib, http_client=self.http_client)

        self.testssl_result = self._run_testssl(args.url)

        # Activate ThreadLocalStdout stdout proxy
        self.thread_local_stdout = ThreadLocalStdout(sys.stdout)
        self.thread_local_stdout.activate()

    def run(self) -> None:
        """Main method"""
        tests = self.args.tests or _get_all_available_modules()
        self.ptthreads.threads(tests, self.run_single_module, self.args.threads)

        self.ptjsonlib.set_status("finished")
        ptprint(self.ptjsonlib.get_result_json(), "", self.args.json)


    def _run_testssl(self, url) -> None:
        """
        Runs testssl.sh against the specified target host with JSON output.

        Checks if 'testssl' is available in the system PATH or current directory.
        If not found, calls self.ptjsonlib.end_error() with an installation hint and aborts.

        The function runs testssl.sh with '--jsonfile' directed to a temporary file and
        '--logfile -' to show live CLI output. After completion, it reads the JSON result
        into memory, deletes the temp file, and returns the parsed JSON data.

        Args:
            target (str): The target hostname or IP address to scan.

        Returns:
            dict: Parsed JSON results from testssl.sh.

        Raises:
            subprocess.CalledProcessError: If the testssl.sh command fails.
        """
        if not shutil.which("testssl"):
            self.ptjsonlib.end_error(
                "testssl.sh is not installed or not found in PATH. Please install it first via `sudo apt install testssl.sh`.",
                self.args.json)
            return

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmpfile:
            json_path = tmpfile.name

        try:
            subprocess.run(
                ["testssl", "--jsonfile", json_path, "--logfile", "/dev/stdout", url],
                check=True
            )
            with open(json_path, "r") as f:
                result = json.load(f)

            return result

        finally:
            if os.path.exists(json_path):
                os.remove(json_path)

    def run_single_module(self, module_name: str) -> None:
        """
        Safely loads and executes a specified module's `run()` function.

        The method locates the module file in the "modules" directory, imports it dynamically,
        and executes its `run()` method with provided arguments and a shared `ptjsonlib` object.
        It also redirects stdout/stderr to a thread-local buffer for isolated output capture.

        If the module or its `run()` method is missing, or if an error occurs during execution,
        it logs appropriate messages to the user.

        Args:
            module_name (str): The name of the module (without `.py` extension) to execute.
        """
        try:
            with self._lock:
                module = _import_module_from_path(module_name)

            if hasattr(module, "run") and callable(module.run):
                buffer = StringIO()
                self.thread_local_stdout.set_thread_buffer(buffer)
                try:
                    module.run(
                        args=self.args,
                        ptjsonlib=self.ptjsonlib,
                        helpers=self.helpers,
                        testssl_result=self.testssl_result
                    )

                except Exception as e:
                    print(e)
                    error = e
                else:
                    error = None
                finally:
                    self.thread_local_stdout.clear_thread_buffer()
                    with self._lock:
                        ptprint(buffer.getvalue(), "TEXT", not self.args.json, end="\n")
            else:
                ptprint(f"Module '{module_name}' does not have 'run' function", "WARNING", not self.args.json)

        except FileNotFoundError as e:
            ptprint(f"Module '{module_name}' not found", "ERROR", not self.args.json)
        except Exception as e:
            ptprint(f"Error running module '{module_name}': {e}", "ERROR", not self.args.json)



def _import_module_from_path(module_name: str) -> ModuleType:
    """
    Dynamically imports a Python module from a given file path.

    This method uses `importlib` to load a module from a specific file location.
    The module is then registered in `sys.modules` under the provided name.

    Args:
        module_name (str): Name under which to register the module.

    Returns:
        ModuleType: The loaded Python module object.

    Raises:
        ImportError: If the module cannot be found or loaded.
    """
    module_path = os.path.join(os.path.dirname(__file__), "modules", f"{module_name}.py")

    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None:
        raise ImportError(f"Cannot find spec for {module_name} at {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

def _get_all_available_modules() -> list:
    """
    Returns a list of available Python module names from the 'modules' directory.

    Modules must:
    - Not start with an underscore
    - Have a '.py' extension
    """
    modules_folder = os.path.join(os.path.dirname(__file__), "modules")
    available_modules = [
        f.rsplit(".py", 1)[0]
        for f in sorted(os.listdir(modules_folder))
        if f.endswith(".py") and not f.startswith("_")
    ]
    return available_modules

def get_help():
    """
    Generate structured help content for the CLI tool.

    This function dynamically builds a list of help sections including general
    description, usage, examples, and available options. The list of tests (modules)
    is generated at runtime by scanning the 'modules' directory and reading each module's
    optional '__TESTLABEL__' attribute to describe it.

    Returns:
        list: A list of dictionaries, where each dictionary represents a section of help
              content (e.g., description, usage, options). The 'options' section includes
              available command-line flags and dynamically discovered test modules.
    """

    # Build dynamic help from available modules
    def _get_available_modules_help() -> list:
        rows = []
        available_modules = _get_all_available_modules()
        modules_folder = os.path.join(os.path.dirname(__file__), "modules")
        for module in available_modules:
            mod = _import_module_from_path(module)
            label = getattr(mod, "__TESTLABEL__", f"Test for {module.upper()}")
            row = ["", "", f" {module.upper()}", label]
            rows.append(row)
        return sorted(rows, key=lambda x: x[2])

    return [
        {"description": ["Penterep template script"]},
        {"usage": ["ptssl <options>"]},
        {"usage_example": [
            "ptssl -u https://www.example.com",
        ]},
        {"options": [
            ["-u",  "--url",                    "<url>",            "Connect to URL"],
            ["-ts", "--tests",                  "<test>",     "Specify one or more tests to perform:"],
            *_get_available_modules_help(),
            ["", "", "", ""],
            ["-t",  "--threads",                "<threads>",        "Set thread count (default 10)"],
            ["-v",  "--version",                "",                 "Show script version and exit"],
            ["-h",  "--help",                   "",                 "Show this help message and exit"],
            ["-j",  "--json",                   "",                 "Output in JSON format"],
        ]
        }]

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help="False", description=f"{SCRIPTNAME} <options>")
    parser.add_argument("-u",  "--url",            type=str, required=True)
    parser.add_argument("-ts", "--tests",         type=lambda s: s.lower(), nargs="+")
    parser.add_argument("-t",  "--threads",        type=int, default=10)
    parser.add_argument("-j",  "--json",           action="store_true")
    parser.add_argument("-v",  "--version",        action='version', version=f'{SCRIPTNAME} {__version__}')

    parser.add_argument("--socket-address",          type=str, default=None)
    parser.add_argument("--socket-port",             type=str, default=None)
    parser.add_argument("--process-ident",           type=str, default=None)

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprint(help_print(get_help(), SCRIPTNAME, __version__))
        sys.exit(0)

    args = parser.parse_args()
    args.url = urlunparse(urlparse(args.url)._replace(path='', params='', query='', fragment=''))

    print_banner(SCRIPTNAME, __version__, args.json, 0)
    return args

def main():
    global SCRIPTNAME
    SCRIPTNAME = os.path.splitext(os.path.basename(__file__))[0]
    args = parse_args()
    script = PtSSL(args)
    script.run()

if __name__ == "__main__":
    main()
