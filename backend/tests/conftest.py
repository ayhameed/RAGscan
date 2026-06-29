"""Shared test fixtures."""
import pytest

SAMPLE_NESSUS = b"""<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Test Scan">
    <ReportHost name="web-server-01">
      <HostProperties>
        <tag name="host-ip">192.168.1.10</tag>
      </HostProperties>
      <ReportItem port="443" svcName="https" protocol="tcp"
                  severity="3" pluginID="12345" pluginName="OpenSSL RCE">
        <cve>CVE-2022-0778</cve>
        <cwe>295</cwe>
        <description>OpenSSL infinite loop denial of service via crafted certificate.</description>
        <solution>Upgrade OpenSSL to 1.0.2zd, 1.1.1n, or 3.0.2.</solution>
      </ReportItem>
      <ReportItem port="22" svcName="ssh" protocol="tcp"
                  severity="4" pluginID="67890" pluginName="Log4Shell">
        <cve>CVE-2021-44228</cve>
        <description>Remote code execution via JNDI injection in Apache Log4j.</description>
        <solution>Update Log4j to 2.17.1 or later.</solution>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""

SAMPLE_OPENSCAP = b"""<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="test-benchmark">
  <Rule id="rule-sshd-disable-root" severity="high">
    <title>Disable root SSH login</title>
    <description>Root login via SSH should be disabled.</description>
    <fixtext>Set PermitRootLogin no in /etc/ssh/sshd_config.</fixtext>
    <reference href="https://nvd.nist.gov/vuln/detail/CVE-2023-38408">CVE-2023-38408</reference>
  </Rule>
  <Rule id="rule-auditd-enabled" severity="medium">
    <title>Enable auditd service</title>
    <description>Audit daemon should be enabled.</description>
    <fixtext>Run: systemctl enable auditd</fixtext>
  </Rule>
  <TestResult id="result-001">
    <target>test-host</target>
    <target-address>10.0.0.5</target-address>
    <rule-result idref="rule-sshd-disable-root">
      <result>fail</result>
    </rule-result>
    <rule-result idref="rule-auditd-enabled">
      <result>fail</result>
    </rule-result>
  </TestResult>
</Benchmark>"""
