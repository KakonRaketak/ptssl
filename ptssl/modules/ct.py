from ptlibs import ptjsonlib
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Testing for supported ciphers:"


class CT:
    CIPHER_SEC_LEN = 8
    ERROR_NUM = -1

    def __init__(self, args: object, ptjsonlib: object, helpers: object, testssl_result: dict) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.testssl_result = testssl_result

    def _find_section_ct(self) -> int:
        id_number = 0
        for item in self.testssl_result:
            if item["id"] == "cipherlist_NULL":
                return id_number
            id_number += 1
        return self.ERROR_NUM

    def _print_test_result(self) -> None:
        id_section = self._find_section_ct()
        if id_section == self.ERROR_NUM:
            self.ptjsonlib.end_error("testssl could not provide cipher list section", self.args.json)
            return

        for item in self.testssl_result[id_section:id_section + self.CIPHER_SEC_LEN]:
            if item["severity"] == "OK":
                ptprint(f"{item["id"]:<23}  {item["finding"]}", "OK", not self.args.json, indent=4)
            elif item["severity"] == "INFO":
                ptprint(f"{item["id"]:<23}  {item["finding"]}", "WARNING", not self.args.json, indent=4)
                self.ptjsonlib.add_vulnerability(
                    f'PTV-WEB-MISC-{''.join(ch for ch in item["id"] if ch.isalnum()).upper()}')
            else:
                ptprint(f"{item["id"]:<23}  {item["finding"]}", "VULN", not self.args.json, indent=4)
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
    """Entry point for running the CT module (Cipher Test)."""
    CT(args, ptjsonlib, helpers, testssl_result).run()