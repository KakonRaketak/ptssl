"""
Forward Security Test – detects when server does not use FS.
Analyses the FS item of a testssl JSON report to tell
whether the target server offers FS or not.

Contains:
- FST class for performing the detection test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib)
"""

from ptlibs import ptjsonlib
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Testing for supported ciphers:"


class FST:
    """
    FST checks whether the server offers FS or not.

    It consumes the JSON output from testssl and check if FS is offered.
    """
    ERROR_NUM = -1

    def __init__(self, args: object, ptjsonlib: object, helpers: object, testssl_result: dict) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.testssl_result = testssl_result

    def _find_fs(self) -> int:
        """
        Runs through JSON file and finds FS item.
        """
        id_number = 0
        for item in self.testssl_result:
            if item["id"] == "FS":
                return id_number
            id_number += 1
        return self.ERROR_NUM

    def _print_test_result(self) -> None:
        """
        Finds FS item.
        Flags if the FS is offered or not.
        1) OK
        2) INFO - prints warning information
        3) VULN - prints out vulnerable protocol versions
        """
        id_fs = self._find_fs()
        if id_fs == self.ERROR_NUM:
            self.ptjsonlib.end_error("testssl could not provide cipher list section", self.args.json)
            return
        item = self.testssl_result[id_fs]

        if item["severity"] == "OK":
            ptprint(f"{item["id"]:<5}  {item["finding"]}", "OK", not self.args.json, indent=4)
        elif item["severity"] == "INFO":
            ptprint(f"{item["id"]:<5}  {item["finding"]}", "WARNING", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                f'PTV-WEB-MISC-{''.join(ch for ch in item["id"] if ch.isalnum()).upper()}')
        else:
            ptprint(f"{item["id"]:<5}  {item["finding"]}", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                f'PTV-WEB-MISC-{''.join(ch for ch in item["id"] if ch.isalnum()).upper()}')
        return


    def run(self) -> None:
        """
        Prints out the test label
        Execute the testssl report function.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)
        self._print_test_result()
        return


def run(args, ptjsonlib, helpers, testssl_result):
    """Entry point for running the FST module (Forward Security Test)."""
    FST(args, ptjsonlib, helpers, testssl_result).run()