# Hardening a public form on Cloudflare

**Turnstile, the Worker proxy hop, rate limiting, validation, and safe output.**
A working pattern, with its reasoning, in one file: [`FORM-HARDENING.md`](FORM-HARDENING.md).

Five layers, cheapest first, on the one surface every project eventually ships — a box a
stranger can type into. Each layer is explained with what it catches, what it does not, and
the trap that cost hours to find.

---

## What is actually in here

The parts you will not find in the vendor documentation, because they only show up once
something is live:

- **The forwarded-IP trap.** A header your CDN owns, overwritten one hop too late, and the
  rate limiter silently stops telling people apart. It looks healthy from every angle except
  the one test that catches it.
- **Uniform refusal.** Divergent error messages draw a map of your defences and hand it over
  one probe at a time. Every refusal looks the same, deliberately.
- **Rate-limit the key the attacker cannot rotate.** Usually not the source IP. Often the
  destination.

Section 14 generalises those three past forms, which is the part worth reading even if you
never ship a form again.

## Where this came from

This came out of one implementation. It is live, it works, and nothing here has been reviewed
by anyone outside the project. The traps are real and were found the hard way. If you deploy
this and learn something it gets wrong, that correction is worth more than the document.

Out of scope, and named as such: CSRF, authentication, file uploads, content filtering, and
the obligations that attach to personal data once you have received it.

Also out of scope here, and covered by the companion: **stored content rendered later** —
admin-authored text on public pages, structured data, and anything held in a database and
escaped at read time. That is [`INPUT-HANDLING.md`](INPUT-HANDLING.md), and it is the harder
half. A mistake in a passing message affects one message; a mistake in stored content sits
in the database waiting, and fixing the bug does not fix the rows.

## "Doesn't publishing your defences help attackers?"

Worth answering rather than assuming away. Every layer here is standard practice, already
published by the vendors and in the OWASP material. What is not public is the configuration,
the thresholds and the keys, and none of those are in this document. A pattern whose security
depends on nobody knowing the pattern is not a defence; it is an accident waiting for its
first curious reader.

## How to read it

Straight through once, then section 12 for adoption order. Section 11 is twelve negative cases,
and they are meant to be watched failing by hand rather than reasoned about — case 6, two
addresses with separate buckets, is the only one that catches the forwarded-IP bug.

The code is illustrative. Read it for the reasoning in the comments rather than as a library
to copy wholesale; there is deliberately no folder of extracted files, because two copies of
a security check is exactly the drift the guide warns about.

## References and further reading

This came out of one working implementation and the failures met while building it. It does
not replace the vendor's own documentation or established application-security guidance, and
where it differs from them it is reporting what one implementation ran into rather than
proposing a standard. Read it alongside:

- Cloudflare Turnstile — [validate the token](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/),
  which is also where the `action` and `hostname` checks in section 5 come from, and
  [hostname management](https://developers.cloudflare.com/turnstile/additional-configuration/hostname-management/),
  which is why the server's check can be tighter than the widget's
- Cloudflare Workers — [context and `waitUntil`](https://developers.cloudflare.com/workers/runtime-apis/context/)
  and [best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/)
- Cloudflare — [HTTP headers](https://developers.cloudflare.com/fundamentals/reference/http-headers/),
  for what `CF-Connecting-IP` is and who is entitled to set it
- OWASP — [Cross-Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html),
  [Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html),
  [SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html),
  [Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html),
  [File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- MDN — [`style-src-attr`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/style-src-attr),
  for what governs an inline style attribute
- [react-markdown](https://github.com/remarkjs/react-markdown), whose own readme is the
  authority on what `rehype-raw` changes about its security posture

## Licence

[CC0 1.0](LICENSE) — public domain, no attribution required, no strings. Take what is useful.

Corrections are more valuable than additions. If a trap here is wrong, out of date, or
specific to a topology in a way the text does not say, that is the thing worth reporting.

---

Published by [Fighting For Sidewalk](https://fightingforsidewalk.com), a venture studio and
technology lab. Companion repositories:
[claude-code-discipline](https://github.com/fightingforsidewalk/claude-code-discipline),
[skill-claude-relay](https://github.com/fightingforsidewalk/skill-claude-relay),
[skill-canonical-tracker](https://github.com/fightingforsidewalk/skill-canonical-tracker).
