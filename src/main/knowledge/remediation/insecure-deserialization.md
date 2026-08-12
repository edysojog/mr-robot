# Insecure Deserialization (CWE-502)

**Root cause:** untrusted bytes/text are deserialized with a format/library that can reconstruct arbitrary objects or trigger code execution as a side effect of deserializing (not just parsing data).

**Fix pattern:** switch to a data-only deserializer for untrusted input; reserve the unsafe/full form for trusted, internal data only.

- Python: replace `pickle.loads`/`yaml.load(data)` on untrusted input with `json.loads` where the data is representable as JSON, or `yaml.safe_load` if YAML is required.
- Java: avoid native `ObjectInputStream.readObject()` on untrusted streams; use a JSON library (Jackson with a fixed set of allowed types, not polymorphic-by-default) or a look-ahead deserialization filter if native serialization can't be avoided.
- Node: avoid `node-serialize`/`eval`-based deserializers entirely; use `JSON.parse` for untrusted input (it can't construct functions/prototypes on its own).
- PHP: avoid `unserialize()` on untrusted input; use `json_decode` instead, or `unserialize($data, ['allowed_classes' => false])` at minimum if the format can't change.
- If the untrusted data must map to typed objects, do it manually (validate fields, then construct the object yourself) rather than letting the deserializer instantiate arbitrary classes.
