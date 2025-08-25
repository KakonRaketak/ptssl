"""
HTTP Redirection Test – checks for redirection from http to https.
Analyses the HTTP status code from a testssl JSON report to tell
whether the target server redirects or not.

Contains:
- HTTPRT class for performing the detection test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib)
"""

from ptlibs import ptjsonlib
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Testing HTTP redirection:"


class HTTPRT:
    """
    HTTPRT checks for redirection from http to https.

    It consumes the JSON output from testssl and check if redirection was detected.
    """
    ERROR_NUM = -1

    def __init__(self, args: object, ptjsonlib: object, helpers: object, testssl_result: dict) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.testssl_result = testssl_result

    def _find_section_https(self) -> int:
        """
        Runs through JSON file and finds HTTP status code.
        """
        id_number = 0
        for item in self.testssl_result:
            if item["id"] == "HTTP_status_code":
                return id_number
            id_number += 1
        return self.ERROR_NUM

    def _print_test_result(self) -> None:
        """
        Finds HTTP status code.
        Flags if redirection was detected.
        1) OK
        2) INFO - prints warning information
        3) VULN - prints out vulnerabilities
        """
        id_https = self._find_section_https()
        if id_https == self.ERROR_NUM:
            self.ptjsonlib.end_error("testssl could not provide http status code", self.args.json)
            return
        item = self.testssl_result[id_https]

        if "301" in item["finding"] or "308" in item["finding"]:
            ptprint(f"HTTP redirect to HTTPS:   OK", "OK", not self.args.json, indent=4)
        elif "302" in item["finding"] or "303" in item["finding"] or "307" in item["finding"]:
            ptprint(f"HTTP redirect to HTTPS:   TEMPORARY (not fully secured)", "WARNING", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                f'PTV-WEB-MISC-{''.join(ch for ch in item["id"] if ch.isalnum()).upper()}')
        else:
            ptprint(f"HTTP redirect to HTTPS:   NO REDIRECTION", "VULN", not self.args.json, indent=4)
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
    """Entry point for running the HTTPRT module (HTTP Redirection Test)."""
    HTTPRT(args, ptjsonlib, helpers, testssl_result).run()