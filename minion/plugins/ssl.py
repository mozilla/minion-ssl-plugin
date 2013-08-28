# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import datetime
import re
import urlparse
import xml.etree.ElementTree as etree

import dateutil.parser
import pytz

from minion.plugins.base import ExternalProcessPlugin


def parse_sslscan_report(path):

    issues = []

    tree = etree.parse(path)
    root = tree.getroot()

    ssltest = root[0]

    #
    # Check if the server supports SSLv2
    #

    supports_sslv2 = False
    for cipher in ssltest.findall('cipher'):
        if cipher.attrib['sslversion'] == 'SSLv2' and cipher.attrib['status'] == 'accepted':
            supports_sslv2 = True
            break
        
    if supports_sslv2:
        issues.append({'Summary':'Server supports obsolete SSLv2', 'Severity': 'High'})

    #
    # Find the certificate
    #

    certificate = ssltest.find('certificate')
    if certificate is None:
        issues.append({'Summary':'Unable to find certificate info', 'Severity': 'Error'})
        return issues

    #
    # Check if the certificate dates are ok. We should probably do this for
    # the whole chain?
    #

    not_valid_before = certificate.find('not-valid-before')
    not_valid_after = certificate.find('not-valid-after')

    not_valid_before_date = dateutil.parser.parse(not_valid_before.text)
    not_valid_after_date = dateutil.parser.parse(not_valid_after.text)

    now = datetime.datetime.now(pytz.timezone('GMT'))

    if now < not_valid_before_date:
        issues.append({'Summary':'SSL Certificate is not yet valid', 'Severity': 'High'})            

    if now > not_valid_after_date:
        issues.append({'Summary':'SSL Certificate is expired', 'Severity': 'High'})            
        
    return issues


class SSLPlugin(ExternalProcessPlugin):

    PLUGIN_NAME = "SSL"
    PLUGIN_VERSION = "0.1"
    PLUGIN_WEIGHT = "light"

    SSLSCAN_NAME = "minion-sslscan"

    def do_start(self):
        sslscan_path = self.locate_program(self.SSLSCAN_NAME)
        if sslscan_path is None:
            raise Exception("Cannot find minion-sslscan on path")
        self.sslscan_stdout = ""
        self.sslscan_stderr = ""
        u = urlparse.urlparse(self.configuration['target'])
        args = ["--no-failed"]
        args = ["--xml=%s/report.xml" % self.work_directory]
        args += ["%s:443" % u.hostname]
        self.spawn(sslscan_path, args)

    def do_process_stdout(self, data):
        self.sslscan_stdout += data

    def do_process_stderr(self, data):
        self.sslscan_stderr += data

    def do_process_ended(self, status):
        if self.stopping and status == 9:
            self.report_finish("STOPPED")
        elif status == 0:
            with open("sslscan.stdout.txt", "w") as f:
                f.write(self.sslscan_stdout)
            with open("sslscan.stderr.txt", "w") as f:
                f.write(self.sslscan_stderr)
            self.report_artifacts("SSLScan Output", ["sslscan.stdout.txt", "sslscan.stderr.txt"])
            self.report_artifacts("SSLScan Report", ["report.xml"])
            issues = parse_sslscan_report("%s/report.xml" % self.work_directory)
            self.report_issues(issues)
            self.report_finish()
        else:
            self.report_finish("FAILED")


if __name__ == "__main__":
    import sys
    print parse_sslscan_report(sys.argv[1])
