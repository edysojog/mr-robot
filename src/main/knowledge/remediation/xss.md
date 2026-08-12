# Cross-Site Scripting (CWE-79)

**Root cause:** untrusted input is written into HTML/DOM/JS context without encoding for that context, so the browser parses it as markup or script instead of text.

**Fix pattern:** encode on output, matched to the sink it lands in — encoding for the wrong context (e.g. HTML-encoding something going into a `<script>` block or an `href`) doesn't protect it.

- DOM sinks: never use `innerHTML`, `outerHTML`, `document.write`, or `insertAdjacentHTML` with untrusted data — use `textContent`/`innerText`, or `createElement` + `setAttribute` for structured content.
- Templating engines (Jinja2, ERB, JSX, Handlebars, EJS): use the auto-escaping output form by default (`{{ }}` / JSX `{expr}`) and only reach for the raw/unescaped form (`|safe`, `<%= raw %>`, `dangerouslySetInnerHTML`) when the value is genuinely trusted markup, not user input.
- Attribute context: quote attributes and HTML-encode the value; don't build `href`/`src` from unvalidated input without also checking the scheme (block `javascript:`).
- If raw HTML from users is a real requirement (e.g. rich text), sanitize with an allowlist-based library (DOMPurify, bleach) rather than hand-rolled regex stripping.
- Set a `Content-Security-Policy` as defense in depth, not as the primary fix.
