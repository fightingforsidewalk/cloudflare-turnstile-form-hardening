# Input handling

**Store what they typed. Make it safe where it lands.**

Companion to [FORM-HARDENING.md](FORM-HARDENING.md).

Version 1.0 · September 2026 · CC0 1.0

That guide covers a public form: a stranger types, a message goes out, nothing is kept.
This one covers everything after that — input that is **stored** and rendered later,
often in a different context, often by a different person, sometimes years later.

It is the harder half, and the reason is simple: in the first case a mistake affects one
message. In this one a mistake sits in your database waiting, and fixing the bug does not
fix the rows.

---

## Provenance and scope

Same as the companion guide: this came out of one implementation, it is live, and
it has not been attacked. Read it as reasoning rather than authority.

Out of scope here: authentication, CSRF, serving user-uploaded files (section 6 covers
*accepting* them, not hosting them), and everything jurisdictional about the personal data
you end up holding.

---

## 0. The frame: sanitising at input is the wrong default

The instinct, when someone says "make sure nothing malicious gets into the form fields," is
to write a function that strips dangerous things on the way in. Scan for `<script>`, strip
HTML tags, escape quotes, reject anything that looks like SQL.

**Do not do this.** It is the single most common architectural mistake in input handling,
and it is wrong for three independent reasons.

**A sanitiser at the door is a blocklist.** It has to anticipate every encoding of every
attack, forever — `<script>`, `<ScRiPt>`, `%3Cscript%3E`, `&lt;script&gt;` double-decoded,
`<img onerror=>`, `<svg onload=>`, unicode homoglyphs, nested tags that reassemble after a
naive strip. Every one you miss is stored. Every one you catch, you had to think of first.

**Escaping at output is an allowlist, and a small one.** It does not need to know what the
attack is. It needs to know what context the text is landing in — HTML body, HTML attribute,
a script element, a SQL value, a shell argument — and each of those has exactly one correct
escaping, defined by the format, known for decades. You are not out-thinking an attacker;
you are following a spec.

**You destroy the original.** A user named `Peters & Sons <Bakery>` types their real name
and you store `Peters &amp; Sons &lt;Bakery&gt;`. Now every read has to guess whether it is
looking at escaped text or literal text, half your surfaces double-escape it, and you can
never recover what they actually typed. Sanitised storage is lossy storage, and the loss
lands on honest users while the attacker just finds the encoding you missed.

**So: store what they typed. Escape where it lands.**

```
  INPUT                    STORAGE                  OUTPUT
  ─────                    ───────                  ──────
  validate SHAPE           store VERBATIM           escape for THIS context
  (type, length, enum)     (what they typed)        (HTML / JS / SQL / email / log)
  normalise NOISE
  (control chars, trim)
```

### The one thing you do change at input: noise, not meaning

There is a narrow exception, and section 3 is entirely about it. You *do* strip control
characters. You *do* trim and collapse whitespace. You *do* cap length. The test that
separates this from sanitising:

> **Normalisation must change no meaning that anybody intended.**

Nobody intends a NUL byte in the middle of their name. Nobody intends three trailing
spaces. Everybody who types `<` in a company name intends it.

### Trust level is not the argument

The other instinct worth killing early: *"that field is admin-only, so it does not need
handling."*

An admin account is **a smaller attack surface than an anonymous one, not a safe one.** Three
reasons, all ordinary rather than paranoid:

- An admin account can be compromised, and when it is, every field they can write becomes
  attacker-controlled with your trust already attached.
- A curator pasting formatted text from a web page, a Word document or a CMS is the *normal*
  case, not the adversarial one, and paste carries markup.
- Content authored by a trusted account and rendered to the public is the classic stored-XSS
  shape. The attacker is not your admin; the victim is every visitor.

---

## 1. Three questions to ask of every field

Before writing any handling code, answer these. Most bad decisions come from skipping the
first one.

**1. What language does this land in?** Not "is this dangerous" but "what parser eventually
reads this string?" HTML body text, an HTML attribute, the raw text of a `<script>` element,
a JSON document, a SQL statement, a shell command line, a filename, a log line, an email
template, a CSV cell that a spreadsheet may evaluate as a formula. Each has its own escaping
and they are not interchangeable.

**2. Who authors it, and who reads it?** Four combinations, and one is dangerous:

| | read internally | read publicly |
|---|---|---|
| **written by a stranger** | moderate — your staff are the victims (see the companion guide on defanging) | **highest** — stranger to public, no gate at all |
| **written by an admin** | low | **high** — this is stored XSS, and it is the one people skip |

**3. Is it stored?** If it is, the bug outlives the fix. Patch the render path and the rows
are still there, waiting for the next render path somebody writes.

---

## 2. Output contexts, one at a time

### 2a. JSX / React text — escaped by default, so store verbatim

React escapes text children. `{user.name}` cannot produce markup, whatever it contains. This
is why plain-text fields need no escaping at all *on this path*:

```ts
// PLAIN TEXT, STORED VERBATIM. Nothing is stripped, escaped or rewritten on the way in —
// React escapes on the way out, and every surface that renders this is JSX. Sanitising at
// the boundary would corrupt the honest case (an ampersand, a quote, a name with a `<` in
// it) to defend against a rendering bug that does not exist; the day someone renders this
// with dangerouslySetInnerHTML, the fix is that call site, not this function.
```

Write that reasoning down next to the field, because the safety property depends on a fact
about *every current render site* and nothing enforces it. The comment is what tells the
next person that reaching for `dangerouslySetInnerHTML` here has a cost.

### 2b. Markdown rendered to a public page — the sanitiser is an absence

This is the most common stored-XSS seam in a modern app, and the defence is unusual: it is
maintained by **what you do not add**.

```tsx
{/* ── THIS IS THE XSS BOUNDARY, AND THE SANITISER IS AN ABSENCE ──────────────
    body_markdown is ADMIN-authored but PUBLIC-rendered, and it is stored RAW
    (the API deliberately does not sanitise). So this render is where it is made
    safe, and the mechanism is what is NOT here:

      · NO rehype-raw, and no other raw-HTML plugin. Without one, react-markdown
        does not parse embedded HTML at all — a pasted <script> or <img onerror=…>
        is escaped and painted as literal TEXT. Adding rehype-raw to "support a
        little HTML" would turn every one of those into live markup in one line.
      · NO dangerouslySetInnerHTML anywhere on this path.
      · The renderer's DEFAULT url transform is left alone — it is what neutralises
        javascript: and other dangerous protocols in links and images. Do not pass
        urlTransform to loosen it.

    Trust level is not the argument. */}
<ReactMarkdown
  components={{
    a({ href, children }) {
      const isExternal = typeof href === 'string' &&
        (href.startsWith('http://') || href.startsWith('https://'))
      return isExternal
        ? <a href={href} target="_blank" rel="noopener noreferrer">{children}</a>
        : <Link href={href ?? '#'}>{children}</Link>
    },
  }}
>
  {body}
</ReactMarkdown>
```

**A safety property held by an absence is fragile in a specific way.** Nothing fails when
someone adds the plugin. No test goes red. The feature request that causes it will be
entirely reasonable — "the marketing page needs a centred div" — and the person implementing
it will not know that one line just turned every stored `<script>` in the database live. So
the comment has to sit at the call site, and it has to say what adding the plugin costs, not
merely that it is disallowed.

**`rel="noopener noreferrer"` on external links** stops the opened page reaching back through
`window.opener` to navigate yours. Modern browsers default `noopener` for `target="_blank"`,
but stating it costs nothing and covers the older ones.

**If you genuinely need raw HTML in markdown**, the answer is not "add rehype-raw and hope" —
it is a real sanitiser (`rehype-sanitize` with an explicit allowlist schema) applied *after*
the raw plugin, with the allowlist reviewed as a security artefact. That is a much larger
commitment than it looks and it is worth avoiding.

### 2c. A `<script type="application/ld+json">` block — the one nobody knows about

This is the best-hidden stored-XSS hole in a site with structured data, and almost every
implementation has it.

**`JSON.stringify` does not escape `<`.** It is a JSON serializer, and `<` is a perfectly
ordinary character in a JSON string; escaping it is not its job. But the browser's HTML
parser does not know it is looking at JSON. It scans the raw text of a `<script>` element
for the literal `</script` and **ends the element there**, wherever it appears.

So a stored field carrying

```
</script><img src=x onerror=alert(1)>
```

serializes to exactly those bytes, the parser closes the script early, and the rest parses as
live HTML. That is stored XSS, and it does not require the attacker to touch the page — only
to get that string into a field the page later renders.

And a JSON-LD block *has* to go out through `dangerouslySetInnerHTML`, because the content of
a `<script>` element is raw text rather than markup, so React cannot render it as children.
There is no way around the injection. There is only escaping it correctly.

```ts
// Every character replaced below is one that cannot appear in JSON's STRUCTURAL syntax
// ({ } [ ] " : , and whitespace), so a global replace can only ever touch string CONTENT.
// That is what makes this safe to apply to the whole serialized document rather than
// field by field.
//
// Written with \u ESCAPE SEQUENCES rather than the literal characters on purpose: U+2028
// and U+2029 are INVISIBLE in an editor and in a diff, so a literal one here would be
// unreadable, trivially deleted by accident, and impossible to review.
const HTML_UNSAFE = /[<>&\u2028\u2029]/g

const ESCAPES: Record<string, string> = {
  '<': '\\u003c',
  '>': '\\u003e',
  '&': '\\u0026',
  '\u2028': '\\u2028',
  '\u2029': '\\u2029',
}

/** Use this INSTEAD OF JSON.stringify for every ld+json block. */
export function jsonLdScript(value: unknown): string {
  return JSON.stringify(value).replace(HTML_UNSAFE, ch => ESCAPES[ch])
}
```

**Why this is the right layer, and not "validate the input instead":** the breakout is a
property of the **serialization context**, not of any one field. Every current and future
field on every JSON-LD block would otherwise need its own guard, and the day someone adds a
new one they will not know to add it. Fixing it at the single point where objects become
script-tag text makes it structural.

**Why it does not affect your structured data.** `<` *is* the JSON escape for `<`. A
JSON parser — including the search engines' — decodes it back before anything looks at the
value, so the parsed data is byte-identical. Only the HTML parser, which never decodes JSON
escapes, sees something different: a string in which it cannot find `</script`.

`&` is escaped because it is the entity introducer and some contexts decode entities before
the script text is read. U+2028 and U+2029 are legal inside a JSON string but are line
*terminators* in JavaScript, so they break any context where the payload is read as JS rather
than JSON — they cannot bite in `ld+json` today, and they are escaped anyway because this
helper is the obvious thing to reach for the first time someone inlines JSON into a real
script block.

### 2d. HTML email

Covered in the companion guide, section 8: escape everything, defang URLs on the raw text
*before* escaping, convert newlines last, fixed recipient, subject from a validated enum.
The one line worth repeating here is that **defanging is aimed at the human reader, not the
renderer** — escaping stops the markup executing, defanging stops your own colleague clicking
a phishing link in what looks like a customer enquiry.

### 2e. SQL — usually nothing to do, and exactly one place to look

If you use a query builder or an ORM, values are bound as parameters and injection is not
available. The defence is the tool, and there is nothing to add.

The whole of your risk is in two places:

**Raw string building.** Any query assembled with template interpolation or `+`. Grep for
it; there should be zero.

**The escape hatch.** Most builders have a `sql.raw()` or equivalent that splices text
directly. Its legitimate use is **identifiers** — a column or table name your own code chose —
because identifiers cannot be bound as parameters. That is fine. What is never fine is a
user-supplied value, or a user-supplied *identifier*, reaching it:

```ts
// LEGITIMATE — the column name comes from our own code, never from a request.
sql`to_char(${sql.raw(column)}, 'HH24:MI')`

// NEVER — a sort column from a query string, a table name from a path parameter.
// If you must, map the input through an allowlist to a constant your code owns:
const COLUMN = { name: 'display_name', created: 'created_at' } as const
const col = COLUMN[input as keyof typeof COLUMN]
if (!col) return validationError(c)
```

Audit the escape hatch by name, once, and write down what you found. It is a five-minute grep
that answers a question people otherwise worry about for years.

### 2f. A URL that will be rendered as an href

From the companion guide, worth restating because it is the one validation subtlety that
catches experienced people: `z.string().url()` (and the `URL` constructor beneath it) asks
"is this a well-formed URL", and `javascript:alert(1)` and `data:text/html,...` are both
well-formed URLs. If the field is ever rendered as an `href`, add the scheme check:

```ts
const editorialUrl = z.string().url().max(500)
  .refine(u => /^https?:\/\//i.test(u), { message: 'Must be an http(s) URL' })
```

Close it at storage time so the database never holds a non-http(s) scheme in the first place,
*and* rely on your renderer's URL transform at output. Both, because either alone fails: the
schema does not cover rows written before it existed, and the renderer does not cover the day
someone builds an anchor by hand.

### 2g. Logs

Two failures, both quiet:

**Control characters and newlines** in a logged value let an attacker forge log lines — write
a newline plus a plausible timestamp and prefix, and your log now contains an entry that
never happened. Strip control characters from anything user-supplied before it is logged.

**PII by accident.** The message body, the email address, the session token. Log an event and
a count, not a payload. A log is a copy of your data with a different retention period, a
different access control, and usually a third-party processor attached.

### 2h. Filenames and paths

Any user-supplied string that becomes part of a path needs an allowlist (`[A-Za-z0-9_-]+` or
tighter) **and** a containment check — resolve the final path and assert it stays inside the
intended base directory. Two layers, never one, and test them with `../../x`, `x/../../y` and
`..` until you have watched each one refuse.

---

## 3. Normalisation: the narrow set of things you do change

Everything in this section changes the stored bytes. Each one passes the test: *no meaning
anybody intended is altered.*

```ts
export const NAME_MAX = 60

/**
 * A submitted name as it should be STORED, or null for "unnamed".
 *
 * Returns null for: absent, null, a non-string (a number, an object, an array — anything a
 * hand-rolled request body can carry), whitespace-only, and control-characters-only.
 *
 * NEVER THROWS AND NEVER REJECTS. The caller's job is to store what comes back; there is no
 * error path to handle because there is no input that should cost somebody their submission.
 */
export function normalizeName(input: unknown): string | null {
  if (typeof input !== 'string') return null

  // Control characters FIRST, so a name that is ONLY a newline trims to empty rather than
  // surviving as an invisible one-character name.
  // C0 controls plus DEL, written as ESCAPES rather than literal bytes: a raw NUL in a
  // source file makes it a binary blob to grep and is one careless editor away from being
  // silently eaten. Replaced with a SPACE, not deleted — "A\nB" is two words, not "AB".
  const cleaned = input.replace(/[\u0000-\u001F\u007F]/g, ' ')

  // Collapse the runs that stripping may have produced, then trim. "A\n\nB" becomes "A B",
  // not "A  B" — the person typed one separation, not two.
  const trimmed = cleaned.replace(/\s+/g, ' ').trim()
  if (trimmed === '') return null

  // TRUNCATED, not refused. A label must never cost somebody their work.
  // .slice() cuts UTF-16 code units, so a cap landing mid-surrogate would store half an
  // emoji. Array.from splits by CODE POINT, which keeps the character whole.
  const points = Array.from(trimmed)
  return points.length <= NAME_MAX ? trimmed : points.slice(0, NAME_MAX).join('')
}
```

Seven decisions in twenty lines, and each is worth stating:

**One function, every write path.** Three call sites applying a cap by hand is three places
for the cap to drift, and the one that drifts is the one nobody tested. Same reasoning as
"one copy of the bot check" in the companion guide.

**Control characters are replaced with a space, not deleted.** `"A\nB"` is two words. Deleting
the newline makes `"AB"`, which is a word nobody typed.

**Escapes, not literal characters, in the source.** A raw NUL turns your source file into a
binary blob as far as `grep` is concerned, and an invisible character is one careless editor
away from being silently removed. This applies doubly to U+2028 and U+2029 in section 2c.

**Empty-after-trim becomes null.** A field somebody cleared and a field they never filled
are the same intention — "I have nothing here" — and both must reach the same state, or one
surface shows a blank and the other shows your fallback.

**Truncate rather than reject.** A 61-character optional label should not cost somebody the
whole submission. Refusing protects nothing; the cap exists for storage and layout, and
both are satisfied by cutting.

**Code points, not code units.** `String.prototype.slice` cuts UTF-16 units, so a cap landing
in the middle of a surrogate pair stores half an emoji — which is not a character, breaks
JSON round-trips in some stacks, and looks like corruption to the user. `Array.from` splits
by code point.

**Never throws, never rejects.** Everything has a defined result, including the values a
hand-rolled request body can carry. There is no error path for the caller to handle because
there is no input that should fail here.

### Enforcement versus the courtesy mirror

The client's `maxLength` and the server's cap are **not the same control**. The client one is
a courtesy so the browser stops typing where the server stops storing; the server one is the
enforcement and runs whatever the client did. Say which is which in a comment, because a
future reader will otherwise assume the client one does something.

The same applies to any limit you mirror across a boundary — a date picker that offers a date
the API rejects is a dead end the user walks straight into, so the two sides should read the
same module rather than two copies of a number.

---

## 4. Validation versus rules: draw the line deliberately

A schema validates a **body**. It sees the request and nothing else. So anything that depends
on state the schema cannot see — who is signed in, what tier they are on, what already exists
in the database — is **not the schema's job**, and trying to make it one produces a schema
that quietly needs a database connection.

The split that works:

- **The schema admits the widest legitimate case**, and is deliberately loose where a rule
  will tighten it. A sanity bound against a megabyte of text arriving, not the real limit.
- **The route refuses against the caller's actual entitlement**, with one module owning the
  numbers so the two sides cannot drift.
- **The rule normalises**, per section 3, rather than rejecting, wherever rejecting would
  cost the user something disproportionate.

Worked example: a display name field. The schema caps at 200 (sanity), the normaliser
truncates at 60 (the rule), and the client's `maxLength` is 60 (the courtesy). A 61-character
name is stored as 60 characters rather than producing a 400 that costs somebody their work,
and a 200,001-character body is refused at the door before anything allocates.

Floors that need no session stay in the schema forever — a date in the past is malformed for
everybody, at every tier.

---

## 5. Two gates, two questions

An admin surface needs both, and they are not substitutes:

- **"Are you one of our callers?"** — the origin lock from the companion guide, section 4. A
  shared secret held by your own server-side proxies, failing closed at startup, answering
  404 rather than 403.
- **"Is this specific request authorised to administer?"** — an admin token or session check
  on top.

Neither replaces the other. The first stops a stranger reaching the endpoint at all; the
second stops one of your own surfaces doing something it should not. And both answer **404**
on failure, because a 403 confirms the endpoint exists and is worth attacking.

---

## 6. Binary input: re-encoding as sanitisation

Images are the common case and the pattern generalises to any binary format.

**Never trust the declared type.** `Content-Type` and the file extension are both
attacker-supplied. Read the actual format from the bytes.

**Check metadata before decoding pixels.** A decompression bomb is a small file that expands
to gigapixels and takes the process down. Reading the header first, and refusing on the
declared dimensions, costs nothing:

```ts
let inputFormat: string | undefined
try {
  const meta = await sharp(input).metadata()   // header only — no pixel decode yet
  inputFormat = meta.format
} catch {
  return c.json({ error: 'Not a supported image' }, 400)
}
if (!inputFormat || !ACCEPTED_INPUT_FORMATS.has(inputFormat)) {
  return c.json({ error: 'Not a supported image — use JPEG, PNG, or WebP' }, 400)
}
```

**Re-encode, always.** Decode, transform, re-encode. The file you store is one *your* library
produced, not one they uploaded — which means a polyglot file (valid image, also valid
something-else), a payload in a comment chunk, and a malformed structure aimed at a downstream
decoder all cease to exist. This is the single highest-value step and it is usually free,
because you were going to resize anyway.

**Order matters for metadata.** Most libraries strip EXIF by default — which is what removes
the photographer's GPS coordinates and timestamp from a phone photo, and is a privacy control
rather than a size optimisation. But orientation lives in EXIF too, so rotation has to run
**first**, baking orientation into the pixels while that metadata still exists. Strip first and
portrait photos come out sideways.

```ts
// .rotate() FIRST: bakes EXIF orientation into the pixels while that metadata still exists.
// Everything after it emits a file with NO EXIF/GPS/XMP at all, because the library discards
// metadata by default and we never ask it not to.
```

Do not call `.withMetadata()` or `.keepExif()` to "preserve quality". You would be preserving
your users' home addresses.

**Serving is a separate problem.** Storing a safe file does not make it safe to serve from
your own origin — that is a different document, and the short version is: a different
hostname, a restrictive `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, and an
explicit `Content-Type` you chose rather than one you stored.

---

## 7. Content you did not write and a user did not type

Machine-generated content — an LLM proposal, an enrichment from a third-party API, an import
from a partner feed — is **input**, and it gets the same treatment. It tends to skip
validation because it feels like it came from inside the house.

It did not. It came from a model that can be prompted by the very user-submitted text it is
summarising, or from a vendor whose escaping you have never audited. Two habits:

**Validate the proposal before it is stored**, with the same schema discipline as a form body,
and reject rather than clean — there is a generator you can ask again, which is exactly the
situation where rejecting costs nothing.

**Run a health check over what is already stored.** A field that should contain one plain
sentence can be checked for control characters, stray quotes, truncation and length, and the
check can run over the whole table rather than one row. This is how you find out that a
pipeline has been storing damaged text for a month:

```ts
const MALFORMED = /[\u0000-\u001F"]/
// Checked FIRST, because it is the certain one: a control character or a quote is not a
// judgement call, it is damage.
```

The general shape: for stored content, **a validator at the door and an auditor over the
table** answer different questions. The door tells you what is arriving. The table tells you
what you already have.

---

## 8. Proving it: the negative cases

As in the companion guide — every one of these must be *watched failing*, not assumed.

1. **Store `</script><img src=x onerror=alert(1)>` in a field that reaches a JSON-LD block.**
   View source. The `<` must appear as `<` and the script element must close where you
   expect. This is the one that is most often broken and never noticed.
2. **Store `<script>alert(1)</script>` and `<img src=x onerror=alert(1)>` in a markdown field
   and render the public page.** Both must appear as literal text.
3. **Store a markdown link with a `javascript:` href.** The rendered anchor must not carry it.
4. **Store a name containing `<`, `&`, a quote and an emoji.** It must round-trip byte-exact
   and render correctly. This is the test that catches over-sanitising, and it is the one
   nobody writes because it does not feel like a security test.
5. **Store a name of exactly the cap length ending in an emoji.** No half surrogate.
6. **Submit a name that is only a newline.** Must land as null, not as a one-character
   invisible name.
7. **Grep for raw SQL construction and for the builder's raw escape hatch.** Every hit must be
   an identifier your own code owns. Record the result.
8. **Upload a valid image with EXIF GPS data.** Download what you stored and confirm the GPS
   is gone and the orientation is right.
9. **Upload a file with an image extension that is not an image.** Must be refused on the
   actual bytes, not the name.
10. **Add `rehype-raw` locally, run test 2, and watch it turn live.** Then remove it. Doing
    this once is what makes the absence in section 2b a real control in your head rather than
    a comment you skim.

---

## 9. The general forms

**Sanitising at input is a blocklist; escaping at output is a spec.** One asks you to
out-think every attacker forever. The other asks you to read a document about a format.

**Store what they typed.** The honest user's ampersand and the attacker's angle bracket are
the same bytes at rest. Which one is dangerous is decided entirely by where it is rendered.

**Normalisation must change no meaning anybody intended.** That is the whole test for what
belongs at input.

**A safety property held by an absence needs a comment at the call site.** Nothing fails when
someone adds the plugin, so the only warning is the one you wrote.

**Fix it at the serialization boundary, not field by field.** If the hazard is a property of
the context rather than of any one value, guarding the values means guarding all of them
forever, including the ones not written yet.

**Trust level is not the argument.** A smaller attack surface is not a safe one, and the
victim of an admin-authored stored payload is the public.

**Re-encoding is the strongest sanitisation available**, because the artefact you keep is one
you produced. Where you can re-encode instead of inspect, do.

**Truncate rather than reject, where rejecting costs the user more than the limit protects.**

**A validator at the door and an auditor over the table answer different questions.** You need
both, and finding out which one you are missing usually means reading your own data.

---

## Licence

CC0 1.0, same as the rest of this repository; no attribution required. Offered as a
description of what worked for one implementation, without any assurance that it will work
for you.
