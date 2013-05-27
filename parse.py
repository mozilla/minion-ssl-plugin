#!/usr/bin/env python

import xml.etree.ElementTree as etree

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

    return issues
    

print parse_sslscan_report("/tmp/report1.xml")
