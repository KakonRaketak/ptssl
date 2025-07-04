"""
Protocols Test – detects insecure TLS/SSL versions
Analyses the `protocols` section of a testssl JSON report to tell
whether the target server still offers outdated or vulnerable protocol
versions.

Contains:
- PT class for performing the detection test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib)
"""

from ptlibs import ptjsonlib
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Testing for allowed protocols:"

class PT:
    """
    PT checks whether the server offers only safe protocols.

    It consumes the JSON output from testssl and flags any insecure protocol versions.
    """

    def __init__(self, args: object, ptjsonlib: object, helpers: object, testssl_result: dict) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.testssl_result = testssl_result

    def _print_test_result(self) -> None:
        """
        Looks at every protocol report from testssl JSON output.
        1) OK
        2) INFO - prints warning information
        3) VULN - prints out vulnerable protocol versions
        """
        for item in self.testssl_result[3:9]:
            if item["severity"] == "OK":
                ptprint(f"{item["id"]:<7}  {item["finding"]}", "OK", not self.args.json, indent=4)
            elif item["severity"] == "INFO":
                ptprint(f"{item["id"]:<7}  {item["finding"]}", "WARNING", not self.args.json, indent=4)
                self.ptjsonlib.add_vulnerability(
                    f'PTV-WEB-MISC-{''.join(ch for ch in item["id"] if ch.isalnum()).upper()}')
            else:
                ptprint(f"{item["id"]:<7}  {item["finding"]}", "VULN", not self.args.json, indent=4)
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
    """Entry point for running the PT module (Protocol Test)."""
    PT(args, ptjsonlib, helpers, testssl_result).run()