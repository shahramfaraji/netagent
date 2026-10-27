# sample-synthetic.cklb — provenance and license

- Source: MITRE `hdf-libs`, path `hdf-converters/converters/cklb-to-hdf/fixtures/input/firefox-stig.cklb`
  (https://github.com/mitre/hdf-libs)
- License: Apache License 2.0, Copyright (c) 2025 The MITRE Corporation.
  Full text: http://www.apache.org/licenses/LICENSE-2.0 . The file is copied unmodified.
- Content: a SYNTHETIC checklist (Mozilla Firefox STIG, 6 rules, host EXAMPLE-HOST, 192.0.2.10).
  It contains no real device data. It is a converter test fixture, not a real assessment.
- Covers all four statuses: open, not_a_finding, not_applicable, not_reviewed.
- cklb_version: 1.0

## Caveat
This is a fixture made for a converter test suite, not a file exported by DISA STIG Viewer 3 itself.
Validate the generated NetAgent output by importing it into STIG Viewer 3 once, and compare any
extra fields a real export contains.
