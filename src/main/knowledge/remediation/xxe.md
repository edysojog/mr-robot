# XML External Entity Injection (CWE-611)

**Root cause:** an XML parser resolves external entities/DTDs while parsing untrusted XML, letting an attacker-supplied document read local files, hit internal URLs (SSRF), or exhaust resources (billion-laughs).

**Fix pattern:** disable external entity resolution and DTD processing at the parser level — this is a parser configuration fix, not an input-validation fix.

- Java (`DocumentBuilderFactory`/`SAXParserFactory`/`XMLInputFactory`): disable DOCTYPE declarations (`setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`) or at minimum disable external general/parameter entities and external DTD loading.
- Python (`lxml`/`xml.etree`): use `lxml.etree.XMLParser(resolve_entities=False, no_network=True)`, or switch `xml.etree.ElementTree` usage to `defusedxml`.
- Node (`libxmljs`/`xml2js`): ensure `noent`/entity expansion options are off; prefer libraries that disable external entities by default and confirm the version in use does.
- .NET: set `XmlResolver = null` on `XmlReaderSettings`/`XmlDocument`.
- If the app doesn't actually need DTDs or external entities (most don't), disabling them outright is the correct fix, not a workaround.
