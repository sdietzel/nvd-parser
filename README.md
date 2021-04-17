# Parser for NVD security advisories

## Installation

- Install dependencies `gem install json mail`.
- Set environment variable `NVD_MAIL_TO` to mail address or leave blank to output to `STDOUT`.
- Copy example config `nvd-config.example.json` to `nvd-config.json` and adapt to your needs.

## Config and use

### CVE Feed

The script expects an unzipped JSON file with CVEs either as `STDIN` or as parameter. Example use with NIST feed:

```bash
curl --silent -L https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz | gunzip | ./nvd-parser.rb
```

### Products

Products are listed as an array, each entry is according to CPE: https://nvd.nist.gov/products/cpe

All matches are partial.

**Example:** `apple:iphone_os:` will match vulnerabilities in all versions of iOS.

### Minimum Score and Vector

Values for minimum score and required attack vectors according to: https://www.first.org/cvss/v3.1/specification-document

Possible values can be found here: https://www.first.org/cvss/calculator/3.0

**Example:** `["AV:N", "PR:N"]` will filter for all vulnerabilities that have an **A**ttack **V**ector type **N**etwork and **P**rivileges **R**equired are **N**one.



## Caching

Each vulnerability will only be mailed once. A database of already sent CVE IDs is maintained in `nvd-db.json`.