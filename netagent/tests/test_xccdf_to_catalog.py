import hashlib
import json
import unittest

from tools.xccdf_to_catalog import CatalogError, build_catalog, clean_markup, infer_catalog_version, parse_xccdf


def fixture(control="V-123456", rule="SV-123456r1_rule", severity="medium", stig_id="CISC-L2-000010"):
    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1"
           id="Cisco_IOS_Switch_L2S_STIG">
  <status date="2026-01-01">accepted</status>
  <title>Cisco IOS Switch L2S Security Technical Implementation Guide</title>
  <plain-text id="release-info">Release: 2 Benchmark Date: 01 Jan 2026</plain-text>
  <version>3</version>
  <Group id="{control}">
    <title>SRG-TEST</title>
    <Rule id="{rule}" severity="{severity}">
      <version>{stig_id}</version>
      <title>Test control</title>
      <description>&amp;lt;VulnDiscussion&amp;gt;A plain explanation.&amp;lt;/VulnDiscussion&amp;gt;</description>
      <ident system="http://cyber.mil/cci">CCI-000001</ident>
      <fixtext>Configure logging.</fixtext>
      <check><check-content>Verify logging is enabled.</check-content></check>
    </Rule>
  </Group>
</Benchmark>
"""
    return xml.encode("utf-8")


class TestXccdfCatalog(unittest.TestCase):
    def test_infer_catalog_version_with_underscores(self):
        self.assertEqual(infer_catalog_version("U_Cisco_IOS_Switch_Y26M04_STIG"), "Y26M04")
        self.assertEqual(infer_catalog_version("Cisco-Y25M10-STIG"), "Y25M10")
        self.assertEqual(infer_catalog_version("no_release_label"), "combined")

    def test_parse_fields_and_severity_mapping(self):
        data = fixture()
        metadata, controls = parse_xccdf(data, "synthetic.xml", hashlib.sha256(data).hexdigest())
        self.assertEqual(metadata["benchmark_id"], "Cisco_IOS_Switch_L2S_STIG")
        self.assertEqual(metadata["release"], "2")
        self.assertEqual(metadata["date"], "01 Jan 2026")
        self.assertEqual(metadata["groups"], 1)
        self.assertEqual(controls[0]["control_id"], "V-123456")
        self.assertEqual(controls[0]["category"], "CAT II")
        self.assertEqual(controls[0]["cci"], ["CCI-000001"])
        self.assertIn("plain explanation", controls[0]["description"])
        self.assertNotIn("<VulnDiscussion>", controls[0]["description"])
        self.assertTrue(controls[0]["hints"]["heuristic"])

    def test_all_severity_categories(self):
        expected = [("high", "CAT I"), ("medium", "CAT II"), ("low", "CAT III")]
        for severity, category in expected:
            with self.subTest(severity=severity):
                data = fixture(severity=severity)
                _, controls = parse_xccdf(data, "synthetic.xml", hashlib.sha256(data).hexdigest())
                self.assertEqual(controls[0]["category"], category)

    def test_deterministic_json_serialization(self):
        data = fixture()
        first = json.dumps(build_catalog([("synthetic.xml", data)], "test"), sort_keys=True, indent=2)
        second = json.dumps(build_catalog([("synthetic.xml", data)], "test"), sort_keys=True, indent=2)
        self.assertEqual(first, second)

    def test_doctype_and_entity_rejected(self):
        unsafe = b'''<!DOCTYPE Benchmark [<!ENTITY xxe "bad">]>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="Cisco_IOS_Switch_L2S_STIG">
<status date="2026-01-01">accepted</status><title>x</title>
<plain-text id="release-info">Release: 1 Benchmark Date: 01 Jan 2026</plain-text>
<version>3</version></Benchmark>'''
        with self.assertRaisesRegex(CatalogError, "DOCTYPE/ENTITY"):
            parse_xccdf(unsafe, "unsafe.xml", hashlib.sha256(unsafe).hexdigest())

    def test_invalid_severity_rejected(self):
        data = fixture(severity="critical")
        with self.assertRaisesRegex(CatalogError, "invalid severity"):
            parse_xccdf(data, "synthetic.xml", hashlib.sha256(data).hexdigest())

    def test_duplicate_ids_rejected(self):
        data = fixture()
        with self.assertRaisesRegex(CatalogError, "duplicate control_id"):
            build_catalog([("one.xml", data), ("two.xml", data)], "test")

    def test_clean_markup(self):
        self.assertEqual(clean_markup("&lt;b&gt;Hello&lt;/b&gt; world"), "Hello world")


if __name__ == "__main__":
    unittest.main()
