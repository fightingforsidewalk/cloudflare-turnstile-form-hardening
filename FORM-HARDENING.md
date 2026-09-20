# Hardening a public form

**Turnstile, rate limiting, validation, and safe output. A working pattern, with its reasoning.**

Version 1.5 · September 2026 · CC0 1.0

---

## Where this came from

This came out of one implementation, one set of forms built carefully. It is live and it
works. Nothing here has been reviewed by anyone outside the project, so read it as reasoning
rather than as authority. The specific traps are real and were found the hard way. If you
deploy this and learn something it gets wrong, that correction is worth more than the
document.

## Scope — what this does NOT cover

This is a complete treatment of five specific layers on one specific surface: a public form
that sends a message. It is **not** a complete treatment of "securing a web form", and
mistaking it for one would be the most likely way to get hurt by it.

Deliberately out of scope, each of which needs its own thinking:

- **CSRF** — relevant the moment your form acts on behalf of a signed-in user. Nothing here
  addresses it.
- **Authentication and session handling** — the rate-limiting section touches auth routes as
  an example, and that is all.
- **File uploads** — a different threat surface end to end: content-type validation, size
  limits, storage isolation, virus scanning, and never serving user content from your own
  origin.
- **Content filtering and spam classification** — this pattern stops *bots*. It does nothing
  about a human writing abuse into your form.
- **Jurisdictional obligations for the personal data you receive** — lawful basis, retention,
  data-subject rights, cross-border transfer. Section 8's "store nothing" advice reduces
  exposure; it does not discharge any of it.
- **Denial of service above the application layer** — that is your CDN's job, not your
  handler's.
- **Stored content rendered later** — admin-authored text on public pages, structured
  data, and anything held in a database and escaped at read time. That is the companion
  document, [INPUT-HANDLING.md](INPUT-HANDLING.md).

The stack shown is a React front end talking to a Hono API through an edge proxy, behind
Cloudflare. The *reasoning* ports anywhere. Some of the *traps* are specific to having a CDN
in front of both ends, and a different topology will have different ones.

---

## 0. What this is, and how to read it

Every venture eventually ships a box on a public page that a stranger can type into and
press send. A contact form, a waitlist, a support request, a data-deletion request. It is
the smallest possible feature and it is the one that gets abused first, because it is the
only door on the building that is deliberately unlocked.

This document is the pattern that came out of building one properly: what each layer is
actually for, what order the layers run in and why the order matters, and the specific
traps that cost real debugging time. The code is TypeScript (React on the front, Hono on
the back), but nothing here is framework-specific — the reasoning ports to anything.

**The one-paragraph version.** A public form needs five independent layers, and they run
cheapest-first: a honeypot (free), a bot challenge verified server-side (one API call), a
per-IP rate limit (a map lookup), schema validation (microseconds), and output escaping
(at the point of rendering). Every layer fails closed. Every refusal returns the same
generic answer, so an attacker learns nothing from the difference between them. The
recipient of the message is fixed in code and never comes from user input.

**The principle underneath all of it:** a defence that cannot be observed failing is not a
defence. Most of the specific advice in this document exists because some layer was
silently not working — running, logging, looking healthy, and not actually distinguishing
between anybody.

---

## 1. The layers, in order, and why the order is the design

```
  browser                          your edge/proxy                  your API
  ───────                          ──────────────                   ────────
  1. honeypot field (hidden)  ──▶
  2. bot widget solves        ──▶  forward real client IP      ──▶  3. rate limit
     token attached                 in YOUR OWN header              4. parse body
                                                                    5. honeypot check
                                                                    6. token verify
                                                                    7. schema parse
                                                                    8. escape + send
```

The order is not arbitrary. It is **cheapest check first, most expensive last**, with one
exception that matters.

**Honeypot before token verification.** The honeypot costs nothing — it is a string
comparison against the empty string. Verifying a challenge token costs an outbound HTTPS
request to a third party. Naive bots fill every field they find, including the invisible
one, so checking the honeypot first means the dumbest half of your traffic never costs you
an API call. This is the single highest-leverage ordering decision in the whole pipeline.

**Rate limit as middleware, before the handler runs.** The limiter is a map lookup and it
protects everything behind it, including the token verification. If you put the limiter
inside the handler after the token check, an attacker with a script can make you do
unbounded outbound requests to Cloudflare. The limiter goes on the route, not in it.

**Schema validation after the bot checks, not before.** This one is genuinely arguable and
the reasoning is worth stating. Parsing is cheap, so you could parse first. But a bot that
sends a malformed body and a bot that fails the challenge should get **the same answer**,
and putting the schema first means your error paths diverge in ways that are observable
from outside. Running the bot checks first and returning the identical refusal from all of
them makes the endpoint uniform. (See section 9 — this is the most under-appreciated idea
in the document.)

**The exception to cheapest-first:** one check that costs real money or sends real email
must be behind *every* other check, always, no matter how cheap it is. Anything that spends
goes last.

---

## 2. The client widget: a reusable challenge field

Most integrations drop the vendor's script tag on one page and move on. That works until
you have a second form, and then a third, and then one of them is inside a modal that
mounts and unmounts. The component below is what survives all of that.

```tsx
'use client'

import { useCallback, useEffect, useRef } from 'react'

const SCRIPT_SRC = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'
const SCRIPT_SELECTOR = 'script[src*="challenges.cloudflare.com/turnstile"]'

declare global {
  interface Window {
    turnstile?: {
      render: (el: HTMLElement, opts: Record<string, unknown>) => string
      remove: (id: string) => void
      reset?: (id: string) => void
    }
  }
}

// Module-scoped so N mounted fields share ONE script tag and one in-flight load.
// Cleared on failure so a later mount can retry.
let scriptLoad: Promise<void> | null = null

function loadApi(): Promise<void> {
  if (typeof window === 'undefined') return Promise.resolve()
  if (window.turnstile) return Promise.resolve()
  if (scriptLoad) return scriptLoad

  const pending = new Promise<void>((resolve, reject) => {
    // The API object appears slightly AFTER script onload — poll for it.
    const waitForApi = () => {
      let attempts = 0
      const poll = setInterval(() => {
        if (window.turnstile) { clearInterval(poll); resolve() }
        else if (++attempts > 50) { clearInterval(poll); reject(new Error('api never appeared')) }
      }, 100)
    }

    if (document.querySelector(SCRIPT_SELECTOR)) { waitForApi(); return }

    const s = document.createElement('script')
    s.src = SCRIPT_SRC
    s.async = true
    s.onload = waitForApi
    s.onerror = () => reject(new Error('script failed to load'))
    document.head.appendChild(s)
  })

  pending.catch(() => { scriptLoad = null })
  scriptLoad = pending
  return pending
}
```

### The four things this solves that a naive integration does not

**One script, many widgets.** The load promise is module-scoped. Three forms on one page
produce one script tag and one in-flight fetch. Without this you get duplicate script
injection, and some vendors respond to that by rendering nothing at all.

**`onload` is not "ready".** The script's load event fires before the global API object is
constructed. Rendering on `onload` intermittently throws "turnstile is not defined" — and
intermittently is the worst kind of bug, because it passes review on a fast connection and
fails for users on a slow one. Polling for the object with a bounded attempt count is ugly
and correct.

**Failure clears the cached promise.** If the script fails once (a blocked network, an ad
blocker, a transient CDN issue), the rejected promise is discarded so a later mount can
retry. A cached rejection means the widget is dead for the rest of the session.

**Retry is bounded.** Fifty attempts at 100ms is five seconds, then it gives up and reports
a null token. It does not poll forever in a background tab.

### The widget itself, and the token lifecycle

```tsx
export function ChallengeField({
  sitekey, onToken, resetKey, theme = 'light', size, action, cData, className, style,
}: ChallengeFieldProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const widgetId = useRef<string | undefined>(undefined)

  // Keep the callback in a ref so an unstable parent function does not
  // re-run the mount effect and rebuild the widget.
  const onTokenRef = useRef(onToken)
  useEffect(() => { onTokenRef.current = onToken })

  const resetWidget = useCallback(() => {
    onTokenRef.current(null)
    if (widgetId.current !== undefined && window.turnstile?.reset) {
      window.turnstile.reset(widgetId.current)
    }
  }, [])

  useEffect(() => {
    if (!sitekey) return
    let cancelled = false

    loadApi().then(() => {
      if (cancelled || !containerRef.current || !window.turnstile) return
      if (widgetId.current !== undefined) return   // already mounted (StrictMode double-invoke)

      widgetId.current = window.turnstile.render(containerRef.current, {
        sitekey, theme,
        ...(size ? { size } : {}),
        ...(action ? { action } : {}),
        ...(cData ? { cData } : {}),
        callback: (token: string) => onTokenRef.current(token),
        // Any of these means the held token is dead. Re-solve and clear it,
        // so a stale token can never be submitted.
        'expired-callback': () => resetWidget(),
        'timeout-callback': () => resetWidget(),
        'error-callback':   () => resetWidget(),
      })
    }).catch(() => { if (!cancelled) onTokenRef.current(null) })

    return () => {
      cancelled = true
      if (widgetId.current !== undefined && window.turnstile) {
        window.turnstile.remove(widgetId.current)
        widgetId.current = undefined
      }
      onTokenRef.current(null)
    }
  }, [sitekey, theme, size, action, cData, resetWidget])

  // Parent-triggered reset. Skips the initial render — mounting already solves.
  const lastResetKey = useRef(resetKey)
  useEffect(() => {
    if (lastResetKey.current === resetKey) return
    lastResetKey.current = resetKey
    resetWidget()
  }, [resetKey, resetWidget])

  return <div ref={containerRef} className={className} style={style} />
}
```

**The contract worth stating explicitly, because it is the whole safety property:**

> The parent receives a fresh token on every successful solve, and `null` whenever the
> token stops being valid — expiry, timeout, error, reset, unmount. **A parent must never
> hold a token this component has not most recently handed it.**

Every branch that could invalidate a token calls back with `null` first and resets second.
There is no path where the parent keeps a token the widget no longer considers live. That
single invariant is what stops the most common real-world failure: a form left open in a
tab for twenty minutes, submitted with a token that expired nineteen minutes ago, failing
verification, and presenting the user with an error they cannot understand or fix.

**The callback-in-a-ref detail.** If you put `onToken` in the effect's dependency array
and the parent passes an inline arrow function, the widget tears down and rebuilds on every
parent render. The user watches the challenge flicker and re-solve. Holding the callback in
a ref and depending only on the configuration values fixes it.

**The StrictMode guard.** React 18 development mode mounts, unmounts and remounts effects
to surface cleanup bugs. Without the `widgetId.current !== undefined` early return you
render two widgets into one container. The guard costs one line.

**`resetKey` is the escape hatch for context.** A token attests to *a* solve, not to *this*
message. If the user changes something that alters what the submission means — the routing
category, the recipient department, the request type — the held token no longer belongs to
the thing being sent. Changing `resetKey` forces a fresh challenge. The same mechanism
burns a spent token after a failed submit:

```tsx
const tsResetKey = `${reason}|${retry}`
```

---

## 3. The form: gating, the honeypot, and burning spent tokens

```tsx
const canSubmit =
  reason && name.trim() && email.trim() &&
  message.trim().length >= 10 &&
  tsToken && status !== 'submitting'
```

The submit button is disabled until every condition holds, **including holding a live
token**. This is a usability control, not a security control — the server re-checks all of
it — but it means a real user never experiences a rejection they could not have predicted.

The honeypot markup:

```tsx
{/* Honeypot — visually hidden from real users, filled by bots */}
<div
  style={{ position: 'absolute', left: '-9999px', width: 1, height: 1, overflow: 'hidden' }}
  aria-hidden="true"
>
  <label htmlFor="app-website">Website</label>
  <input id="app-website" type="text" name="website" autoComplete="off" tabIndex={-1} value="" readOnly />
</div>
```

Five details, each doing work:

- **Off-screen positioning, not `display:none`.** Some bots skip anything with
  `display:none` or `visibility:hidden` because that check is trivial. Off-screen absolute
  positioning renders in the DOM and is filled by naive form-fillers.
- **A plausible field name.** `website`, `url`, `company` — something a form-filler has a
  heuristic for. A field named `honeypot` catches nobody.
- **`aria-hidden` and `tabIndex={-1}`.** Screen readers skip it; keyboard users never tab
  into it. A honeypot that traps an assistive-technology user is a bug that is invisible to
  everyone testing with a mouse.
- **`autoComplete="off"`.** Otherwise a browser's autofill obligingly fills it and locks a
  real user out of your form permanently. This one bites in production, not in testing.
- **`readOnly` with `value=""`, and the tradeoff that comes with it.** The real form always
  submits the empty string, and the field is in the payload so its absence is detectable
  server-side too. The cost is that a bot driving a real browser, honouring ordinary form
  semantics, will skip a read-only input the same way a person would — so this trades some
  of the trap's reach for immunity to a browser autofilling it and locking a real user out.
  A writable field catches more and asks more of your autofill suppression. Pick knowing
  which way you traded; do not copy this one believing it is free.
- **Where the hiding rules live is a security decision, not a styling one.** This is the
  detail that is missing from every honeypot write-up we have read, including the first
  version of this one, and we learned it by shipping the bug. The field lives in the markup.
  If the rules that hide it live in a stylesheet, those are two artefacts on two independent
  cache schedules, and a returning visitor can get new markup against an old stylesheet. When
  that happens the honeypot renders as what it actually is: a visible, labelled text input in
  the middle of your contact form. It is not a disclosure and nobody can exploit it, but a
  trap that announces itself has stopped being a trap, and a real user who fills it in is
  silently refused.

  The example above keeps the rules inline, which is why it is written as a style object
  rather than a class. That makes the pair atomic — markup and its hiding arrive together or
  not at all — and it is the right default. Know what it costs: inline style attributes are
  governed by `style-src-attr`, which falls back to `style-src`, so this needs an allowance
  for inline styles in your Content Security Policy — `'unsafe-inline'` in most deployments,
  or `'unsafe-hashes'` with the attribute's hash if you would rather be narrow about it. That is a real allowance, and the day someone tightens the
  policy — a good instinct, arriving from somewhere else entirely — the honeypot becomes
  visible again, with nothing in either change connecting them.

  So pick deliberately. Either put a content hash in the stylesheet's URL, so markup and CSS
  are always a matched pair and the rules can live in a class under a strict policy; or keep
  them inline and write down, next to the policy, that a control depends on that allowance. Both are
  defensible. What is not defensible is choosing by accident and finding out from a form that
  has been advertising its own honeypot since breakfast.

And the retry path:

```tsx
catch {
  setStatus('error')
  setRetry(n => n + 1)   // burn the spent token — the next submit gets a fresh one
}
```

Challenge tokens are single-use. A retry that re-sends the same token fails verification
100% of the time, and the user sees a form that has decided to reject them forever.
Incrementing a counter that feeds `resetKey` forces a fresh solve.

---

## 4. The proxy hop: forwarding the real client IP

If your browser talks to a server component or edge function which then calls your API,
**everything downstream sees the proxy's IP, not the user's.** This is the trap that
silently destroys per-IP rate limiting, and it destroys it in the worst possible way: the
limiter keeps running, keeps counting, keeps returning 429s — it has just stopped
distinguishing between people. One abuser exhausts the bucket for the entire planet, and
legitimate users collect 429s they did not earn.

### The part that costs a day of debugging

The obvious fix is to set `CF-Connecting-IP` (or `X-Forwarded-For`) on the proxied request.
**If your API also sits behind the same CDN, this is a no-op.** The CDN owns those headers.
It overwrites them with the address that actually opened the connection — your proxy —
before your origin ever sees them. You will read the code, see the header being set, see
the header arriving with a different value, and lose an afternoon.

**The rule:** a header your CDN owns is not a forwarding channel. Use one it does not touch.

```ts
// In the proxy — read the CDN-set header (trustworthy: the CDN strips any
// client-sent copy before it reaches you) and forward it under YOUR OWN name.
export function clientIpOf(req: Request): string | null {
  return req.headers.get('CF-Connecting-IP')
}

// ...then send it as X-APP-Client-IP, a header the CDN does not normalize.
```

```ts
// In the API — prefer your own header, fall back gracefully.
export const CLIENT_IP_HEADER = 'X-APP-Client-IP'

export function clientIpFrom(c: Context): string {
  return (
    c.req.header(CLIENT_IP_HEADER) ??
    c.req.header('CF-Connecting-IP') ??
    c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ??
    'unknown'
  )
}
```

### The security invariant you must write down next to this code

Reading a client IP out of a header the caller controls is normally exactly how an attacker
rotates their way out of a rate limit. It is safe here **for one reason and only one
reason**: an origin lock has already run and rejected any request that did not carry a
shared secret held only by your own server-side proxies. By the time this function is
called, the sender is provably one of yours.

```ts
// SECURITY INVARIANT — READ THIS BEFORE CHANGING ANYTHING NEAR IT.
// This header is trusted ONLY because the global origin lock has already rejected
// anything that did not present APP_PROXY_SECRET. If the origin lock is removed,
// weakened, or a rate-limited route is added to the lock's open-path list, this
// header becomes attacker-controlled and per-IP limiting becomes trivially
// bypassable (send a random IP each request). Delete this preference first.
```

Write that comment. The invariant lives in a different file from the code that depends on
it, which means the person who weakens it will not be looking at the code that breaks.

### The origin lock itself

```
This API is private infrastructure. It has exactly N authorized callers, all
server-side, all holding APP_PROXY_SECRET in env. Nothing else may talk to it,
including a browser.

FAIL-CLOSED: if the secret is absent from env, the module throws at startup rather
than letting the service boot wide open. A gate that silently disables itself when
misconfigured is not a gate.

404, never 401 or 403: a 403 confirms the endpoint exists and is worth attacking.
A 404 says nothing.
```

Two details from running this in production. **Your platform's health check cannot hold a
secret** — it calls from its own infrastructure — so `/health` must be exempt, and it must
therefore leak nothing. **Third-party webhooks are a caller you cannot give a secret to**;
they are registered as a URL and they decide what headers they send. Those endpoints need
their own exemption and their own authentication (signature verification), and they are the
one route a stranger can reach, so they need their own reasoning.

### The sentinel that must not travel

When the IP is genuinely unknown, `'unknown'` is a perfectly good *rate-limit key* —
everyone unidentifiable shares one conservative bucket. It is **not** a good value to send
to a third party:

```ts
// 'unknown' is a sentinel, not an address. Passing it to the challenge vendor's
// siteverify as `remoteip` would be sending a made-up value in a field that is
// allowed to be absent — and a bogus remoteip is strictly worse than none, because
// it invites the very mismatch the parameter exists to detect. Absent means
// "we don't know", which is the truth.
export function optionalClientIp(c: Context): string | undefined {
  const ip = clientIpFrom(c)
  return ip === 'unknown' ? undefined : ip
}
```

Two functions, because the same value means different things in the two contexts. This is
the kind of distinction that looks like over-engineering until the day your challenge
provider starts failing every verification from one region.

---

## 5. Server-side verification: one copy, fail closed

**Write this once.** Before it was extracted, our codebase had four near-identical copies of
these fifteen lines across four routes, differing only in which secret they read and what
they logged. Four copies of a security check is four chances for one to drift, and the drift
that matters here is silent: a copy that returned `true` on a parse failure, or that forgot
the `=== true`, would pass every test its own route has and quietly stop being a bot check.

```ts
const VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'

export interface VerifyOptions {
  /** The NAME of the env var holding this widget's secret — not the secret. */
  secretEnv: string
  /** The visitor's IP. OMITTED when unknown, never sent as a sentinel. */
  ip?: string
  /** Log prefix, so a missing key names the surface that noticed. */
  label: string
  /** If the widget sets `action`, set it here too. Unchecked, it means nothing. */
  expectedAction?: string
  /** The exact host this widget may be solved on. Exact — see below on subdomains. */
  expectedHostname?: string
}

/** True only if the vendor says this token is good. False for every other outcome. */
export async function verifyChallenge(token: string, opts: VerifyOptions): Promise<boolean> {
  const secret = process.env[opts.secretEnv]
  if (!secret) {
    // Loud: this misconfiguration silently disables a whole surface, and this line
    // is the only way anybody finds out before a user does. Names the VARIABLE,
    // never a value.
    console.error(`[${opts.label}] ${opts.secretEnv} not set — rejecting all submissions`)
    return false
  }

  const body = new URLSearchParams({ secret, response: token })
  if (opts.ip) body.set('remoteip', opts.ip)

  try {
    // Bounded, not just fail-closed. Without a deadline, a vendor network problem
    // parks this handler until the platform decides what a timeout means — which
    // on some platforms is never, and on others is a number you did not choose.
    const res = await fetch(VERIFY_URL, {
      method: 'POST',
      body,
      signal: AbortSignal.timeout(10_000),
    })
    const data = await res.json() as {
      success: boolean; action?: string; hostname?: string
    }
    if (data.success !== true) return false

    // The vendor echoes back the action and the hostname the token was solved for.
    // A token is only good for the surface it was issued to, and the only way that
    // holds is if somebody compares. An option the caller sets and nobody checks is
    // worse than no option at all, because it makes them feel covered.
    if (opts.expectedAction && data.action !== opts.expectedAction) {
      console.warn(`[${opts.label}] token action mismatch — rejecting`)
      return false
    }
    if (opts.expectedHostname && data.hostname !== opts.expectedHostname) {
      console.warn(`[${opts.label}] token hostname mismatch — rejecting`)
      return false
    }
    return true
  } catch {
    return false
  }
}
```

### Fail closed is half of it. Fail bounded is the other half.

An outbound call to a third party sits between your visitor and their answer. Fail-closed
says what happens when it returns something wrong. It says nothing about what happens when it
returns nothing at all, and that is the case that hurts: not an error you handle, but a socket
that stays open while your handler waits. On a long-lived server that is a worker tied up per
submission. On a platform with its own request ceiling, it is your visitor watching a spinner
until somebody else's timeout fires — a number you did not pick and probably do not know.

`AbortSignal.timeout` costs one line and converts an unbounded wait into an ordinary failure,
which the fail-closed path already knows how to refuse. Ten seconds is generous for this call;
pick a number and write it down rather than inheriting one.

**If you retry, retry correctly.** The obvious reaction to a timeout is to try again, and the
obvious way to do that is wrong here. Challenge tokens are single-use: replay one and the
vendor answers `timeout-or-duplicate`, which is indistinguishable from an attacker replaying a
spent token. Cloudflare's siteverify takes an `idempotency_key` — a UUID you generate — so the
*validation request* can be retried safely while the token underneath stays single-use. Send
the same key with the retry and the vendor treats it as the same validation rather than a
second one. What it does not do is make the token reusable: that is still one token, one
validation, and a genuine replay still earns `timeout-or-duplicate`. The key makes the
*call* safe to repeat, not the credential.

This pattern is not unique to one vendor. Any single-use credential verified over a network
has the same shape, and the general form is worth carrying: **a retry of a request is not a
retry of the thing the request was about.** If the resource is single-use, the retry needs its
own identity, or it is a second attempt at something that can only happen once.

Not retrying at all is also a defensible answer for a contact form, and it is what the route
in this guide does. Refusing on a vendor timeout costs one visitor one resubmission. What is
not defensible is retrying without the key and then reading the duplicate rejection as a bot.

### What the hostname check is actually for

The obvious objection: the widget's own configuration already lists which hostnames may
solve it, so why compare again on the server. The answer is in how that list matches.
Cloudflare's hostname management says a hostname you add covers **that host and all of its
subdomains** — add `example.com` and the widget works on `www.example.com`,
`shop.example.com` and `any.sub.example.com`. That is a suffix rule, and it is the right
default for a dashboard, because nobody wants to enumerate their own subdomains.

Your server has no such constraint. It can compare for **exact equality against a constant**,
which is strictly tighter than the list that issued the token. A widget embedded on a
subdomain — one that exists today, or one somebody stands up next year — produces a token the
vendor considers valid and your server refuses. That is the one thing the second layer does
that the first cannot, and it is the reason to write it.

Two details that decide whether it works:

**Compare against a constant you hold, never against the request's own `Host`.** Behind a
proxy or a CDN, the `Host` reaching your handler is your API's hostname, not the page the
visitor was looking at. A check written that way refuses every legitimate submission, and it
refuses them in the way that is hardest to diagnose, because the code reads correctly.

**Exact, not `endsWith`.** A suffix comparison recreates the dashboard's rule in your own
code and throws away the only advantage you had. If you genuinely serve several hosts, list
them and match against the set.

### Why one of those options is optional and the other should not be

`expectedHostname` has no dependency on anything in the page: the widget already solves on
whatever host it is embedded in, so the check can ship on its own, today, with nothing else
moving. `expectedAction` does have one — the markup has to carry `data-action` before the
server starts demanding it, and the markup and the server usually deploy by different routes.
Ship the verifier first and every submission is refused until the page catches up.

That is why the action is checked only when the caller supplies an expected one. It is not
laxity; it is what lets a codebase with several surfaces migrate them one at a time instead
of in a single deploy that has to land everywhere at once. The moment a surface's markup
carries its action, that surface's caller passes the expected value and the check is no
longer optional for it.

### Every line, and why it is what it is

**Env read at use, never at import.** A module-scope read makes a missing key an
application-wide boot failure over a contact form. Read at use, it breaks the one path that
needs it and nothing else.

**Fail closed in all four ways it can fail:** no secret configured, a non-2xx or unparseable
answer, a network error reaching the vendor, and a response where success is anything other
than exactly `true`. Every one returns false, and false means the caller refuses. There is
deliberately **no "assume ok if the vendor is down"** branch — an outage that blocks a form
is visible and temporary; one that opens a form to bots is neither.

**`success === true`, not truthiness.** The vendor answers with a JSON object. A body that
failed to parse into what you expect gives `undefined`, and `if (data.success)` treats any
truthy value as a pass. The strict comparison is what makes a malformed answer a refusal
rather than an accident. This is the single most common way a challenge integration is
quietly broken.

**The secret is named by variable, not passed by value.** Callers hand in the *name* of their
env var and this reads it. So no caller holds a secret in a local, no secret can reach a log
line through a caller's error handler, and multiple widget pairs stay visibly separate at
each call site.

**What this file deliberately does not do:** decide what a refusal *means*. A refused publish
is a 400 with words. A refused deletion-request intake is a neutral 200. A refused magic
link is a neutral 200 byte-identical to a successful send. Three different answers to one
boolean, and each belongs to its own route.

---

## 6. Rate limiting

```ts
class RateLimiter {
  private store = new Map<string, { count: number; resetAt: number }>()

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    label: string,
  ) {
    // Purge expired entries every 5 minutes to prevent unbounded Map growth.
    // .unref() so this interval does not prevent clean process shutdown.
    setInterval(() => {
      const now = Date.now()
      for (const [key, entry] of this.store) {
        if (now >= entry.resetAt) this.store.delete(key)
      }
    }, 5 * 60 * 1000).unref()
  }

  check(key: string): { allowed: boolean; resetAt: number } {
    const now = Date.now()
    const entry = this.store.get(key)

    if (!entry || now >= entry.resetAt) {
      const resetAt = now + this.windowMs
      this.store.set(key, { count: 1, resetAt })
      return { allowed: true, resetAt }
    }
    if (entry.count >= this.limit) return { allowed: false, resetAt: entry.resetAt }

    entry.count++
    return { allowed: true, resetAt: entry.resetAt }
  }
}

export function rateLimit(limiter: RateLimiter): MiddlewareHandler {
  return async (c, next) => {
    const { allowed, resetAt } = limiter.check(clientIpFrom(c))
    if (!allowed) {
      return c.json({ error: 'Too many requests' }, 429, {
        'Retry-After': String(Math.ceil((resetAt - Date.now()) / 1000)),
      })
    }
    await next()
  }
}
```

### One bucket per surface, never a shared one

```ts
export const contactWriteLimiter  = new RateLimiter(5,  60_000, 'contact-write')
export const intakeLimiter        = new RateLimiter(3,  60_000, 'dsr-intake')
export const verifyLimiter        = new RateLimiter(10, 60_000, 'dsr-verify')
export const publicReadLimiter    = new RateLimiter(60, 60_000, 'public-read')
export const adminWriteLimiter    = new RateLimiter(30, 60_000, 'admin-write')
```

Separate instances even where the numbers match. Two reasons, and both have bitten us:

**A cheap signal must never be able to throttle a valuable one.** If a high-volume analytics
counter shares a bucket with a funnel event, a burst of counter writes spends the allowance
the funnel event needs — and you lose the measurement that mattered while keeping the one
that did not.

**Two figures read together must be throttled together or not at all.** If you compute a
rate as *A divided by B* and a burst throttles A while leaving B alone, the figure is not
thinned, it is *wrong* — quietly wrong, which is worse than visibly missing.

And the admin case: a public endpoint and an admin endpoint that share a limiter let public
traffic exhaust the admin's budget, and stop the two from ever being tuned apart.

### Sizing, honestly

| Surface | Limit | Reasoning |
|---|---|---|
| Public contact form | 5/min/IP | Challenge and honeypot are the primary defences; this is friction against volume |
| Anything that sends email | 3/min/IP | Every accepted request spends money. Billing surface before security surface |
| Token consumption / verification | 10/min/IP | Tokens are high-entropy; brute force is already infeasible. Defence in depth |
| Public reads | 60/min/IP | Well above any real visitor, well below scraping |
| Third-party webhooks | 300/min/IP | **Generous on purpose — see below** |

**Throttling a webhook makes its backlog worse.** A vendor's deliveries are legitimate
bursts: every subscription renewing at once, a backlog draining after an outage, three days
of retries arriving together. A 429 is a non-2xx, so the vendor keeps retrying and the queue
grows. The limit on a webhook is a **flood ceiling, not a rate policy** — it exists only
because that route is necessarily exempt from your origin lock and is therefore the one
endpoint a stranger can reach at all.

### The second key: rate-limit the thing the attacker cannot rotate

This is the insight worth taking away from the whole section.

Per-IP limiting answers *"how fast may one source ask?"* It cannot answer *"how many
messages may one inbox receive?"* A thousand IPs each spending their allowance on one
victim's email address is a thousand emails, every one of them inside the per-IP rules.

The target address is the one thing an attacker cannot rotate. So it gets its own limiter:

```ts
// 3 sends per ADDRESS per rolling hour. Keyed on the normalized email — never an IP.
// Somebody who did not get the first link asks again; somebody who lost the tab asks a
// third time. A fourth in the same hour is not a person having trouble with their email.
export const addressLimiter = new RateLimiter(3, 60 * 60_000, 'send-per-address')
```

Two ordering notes that are easy to get wrong:

- **Key on a hash of the address, never the plaintext.** `SHA-256(normalized email)` is
  a perfectly good map key and keeps addresses out of process memory in a form anyone can
  read from a heap dump.
- **The per-address limiter goes BEHIND the bot check, not in front of it.** Checked first,
  anyone could burn a victim's three slots with junk requests and lock the real owner out
  of signing in. The bot check is what makes the per-address counter mean something.

### The in-memory caveat, stated plainly

An in-memory map is correct for a single instance and **silently ineffective across
several**. This is not gradual degradation — it is a sudden failure of the guarantee the
moment you scale horizontally, with no error, no log line, and no visible change. The
limit effectively multiplies by your instance count.

Write the trigger down where the code is, not in a ticket:

```
Move to a shared store (Redis/Upstash) when EITHER: the service scales past one
instance, OR authentication is added (brute-force limits must share state across
instances to mean anything).
```

Write the reason, not a reference to where the reason is kept. A citation in code names
something safe to publish — a public URL, a standard anyone can look up, or nothing — never
a repository or vault path, an internal document name, or an organisation you do not name in
public. Comments outlive the boundary they were written inside: this one is legible to
someone who has never seen your issue tracker, which is the test.

Note which layer does *not* have this property: the bot challenge is verified by the vendor,
not by your process, so it holds across any number of instances. That asymmetry is a reason
to lean on the challenge as the primary control and treat the limiter as friction.

---

## 7. Validation at the boundary

```ts
export const contactSchema = z.object({
  reason: z.enum(['General question', 'Feature suggestion', 'Privacy request', 'Sales inquiry']),
  name:            z.string().min(1).max(100),
  email:           z.string().email().max(254),
  message:         z.string().min(10).max(1200),
  challenge_token: z.string().min(1),
  website:         z.literal(''),   // honeypot — bots fill this; must be empty string
})

// Generic 400. The validator's error detail is intentionally discarded —
// no internal detail in error responses.
export function validationError(c: Ctx) {
  return c.json({ error: 'Invalid request' }, 400)
}
```

**Every inbound body is parsed here before any write.** One file holds every schema, so
adding a field to a route means adding it to the schema first — and so a reviewer can read
the entire input surface of the application in one sitting.

**The honeypot is a schema literal.** `z.literal('')` means a body carrying anything in that
field fails to parse. The field is not optional and not merely ignored — its emptiness is
part of the contract.

**Max lengths on everything, including the ones that "can't" be long.** 254 for email is the
RFC maximum. The message cap should match what your UI displays as a counter, so a user is
never surprised. An uncapped string field is an uncapped request body.

### Two validation subtleties that are not obvious

**`z.string().url()` is not a scheme check.** It asks "does the URL constructor accept
this?", and the constructor happily accepts `javascript:alert(1)` and `data:text/html,...`.
Both are valid URLs. If that field is ever rendered as an `href`, you have stored XSS.
Close it at the door:

```ts
const editorialUrl = z.string().url().max(500)
  .refine(u => /^https?:\/\//i.test(u), { message: 'Must be an http(s) URL' })
```

**`.strict()` can be a privacy control, not tidiness.** If a rule says "this endpoint never
records a per-visitor identifier", a strict schema **rejects** a body carrying one rather
than silently stripping it. A future caller that starts sending a session id finds out
immediately, instead of believing it is being recorded. Silent stripping means the rule is
enforced and unobservable; rejection means it is enforced and loud.

---

## 8. Output safety: the message has to land somewhere

The form's job is nearly done, and this is where the remaining interesting vulnerabilities
live — because now attacker-controlled text gets rendered somewhere, usually in an email
client, usually one belonging to you or your staff.

```ts
// Fixed recipient — NOT user-controlled. replyTo is the submitter's validated address.
// HTML-escapes ALL user input. Never auto-links. Content is inert.
export async function sendContactEmail(opts: ContactEmailOptions) {
  return sendEmail({
    to:      'support@yourdomain.com',   // hardcoded. never from the body.
    subject: `[Contact] ${opts.reason}`, // from a validated enum, not free text.
    html:    buildContactHtml(opts),
    text:    buildContactText(opts),
    replyTo: opts.email,
    kind:    'contact_us',
  })
}
```

**The recipient is hardcoded.** If any part of the destination comes from the request body,
you have built an open relay and someone will find it within the week. The user's address
goes in `replyTo`, which is inert.

**The subject line comes from a validated enum**, not from free text. A subject assembled
from user input is a header-injection surface in some mail stacks and an inbox-rule
nightmare in all of them.

### Escape, then defang

```ts
function escHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#x27;')
}

// Full cybersecurity-convention URL defang: break BOTH the scheme AND the dots, so no
// email client can recognize or auto-link any part of the URL.
//   https:// → hxxps://     dots elsewhere → [.]
// Applied to RAW input BEFORE HTML-escaping; brackets and 'x' are not HTML-special.
function defangUrls(s: string): string {
  return s.replace(/https?:\/\/[^\s<>"']+/gi, url =>
    url.replace(/^https:\/\//i, 'hxxps://')
       .replace(/^http:\/\//i, 'hxxp://')
       .replace(/\./g, '[.]'))
}

const msgHtml = escHtml(defangUrls(opts.message)).replace(/\n/g, '<br>')
```

**Order matters: defang first on raw input, then escape.** Defanging works on the raw text
because brackets and the letter x are not HTML-special and survive escaping unchanged.
Reverse the order and your regex is matching against `&amp;`-mangled text.

**Why defang at all, when escaping already prevents script execution?** Because the threat
is not script execution in an email client — it is *you*, or a colleague, clicking a
phishing link in a message that arrived looking like a legitimate customer enquiry. Escaping
makes the content inert to the renderer. Defanging makes it inert to the reader. The form is
a delivery mechanism for links aimed at your own staff, and that is the actual attack anyone
runs against a contact form in 2026.

**Convert newlines last**, after escaping, or your `<br>` gets escaped into visible text.

### What you do not store

```
No message content is stored anywhere — the event log records only that a submission
occurred. The submitter's email is used only as replyTo: never logged, never stored.
```

A contact form does not need a database table. If the message is in an inbox, a copy in your
database is a second place to breach, a second place to search under a data-subject request,
and a second retention period to defend. Log a **count**, not a payload.

---

## 9. Uniform refusal: the idea most implementations miss

Look at the refusal paths in the finished route:

```ts
router.post('/', rateLimit(contactWriteLimiter), async (c) => {
  const raw = await c.req.json().catch(() => null)
  if (!raw || typeof raw !== 'object') return validationError(c)

  // Honeypot first — saves a challenge API call for bot submissions.
  if ((raw as Record<string, unknown>).website !== '') return validationError(c)

  const token = (raw as Record<string, unknown>).challenge_token
  if (typeof token !== 'string' || !token) return validationError(c)

  const ok = await verifyChallenge(token, {
    secretEnv: 'CHALLENGE_SECRET_CONTACT', ip: optionalClientIp(c), label: 'contact',
  })
  if (!ok) return validationError(c)

  const parsed = contactSchema.safeParse(raw)
  if (!parsed.success) return validationError(c)

  logEvent('contact_submitted')          // count only, no PII

  // Best-effort send — never awaited before the response. See the note below
  // this block before copying it into a serverless runtime.
  void sendContactEmail(parsed.data).catch(e =>
    console.warn('[contact] email threw unexpectedly:', e instanceof Error ? e.message : e))

  return c.json({ ok: true }, 200)
})
```

**A promise left floating is safe in a long-lived server and is not safe everywhere.** Say
what this sample assumes, because the first version of this page did not and that omission
was the defect: the route above was written for a long-lived Node process, and it is correct
there. The send is deliberately not awaited, so a slow mail provider cannot hold the response
open, and that works because the process outlives the request. In a serverless runtime it does
not: the platform is entitled to tear the execution context down once you have responded, and
work nobody registered simply stops. On Cloudflare Workers the registration is
`ctx.waitUntil(promise)`; other runtimes have their own, and a queue works everywhere. Await
it, register it, or queue it — the one thing that does not work is leaving it hanging in a
place that ends.

**Malformed JSON, a filled honeypot, a missing token, a failed challenge, and a body that
fails the schema all return the identical response: `400 {"error":"Invalid request"}`.**

A bot probing your endpoint learns nothing about which layer caught it. It cannot determine
whether the honeypot exists, whether the challenge is actually verified server-side, or what
your schema requires. Divergent errors are a map of your defences, drawn by you, handed to
the attacker one request at a time.

This also means **your logs are the only place the distinction lives** — which is correct,
and which is why the "secret not configured" line is `console.error` and names the variable.

### Always 200 on send outcome

```ts
// Best-effort send — never awaited before the response.
// Always returns 200 to the caller regardless of send outcome.
```

The response says "we accepted your message", not "we delivered your message". Two reasons:
the user cannot act on a delivery failure, and awaiting the mail provider ties your response
time to theirs — an outage there becomes a hanging form here. The failure is logged where
you will see it.

For sensitive surfaces, go further. **A refused data-deletion request returns a neutral
200 byte-identical to an accepted one.** Otherwise the endpoint is an oracle: submit an
address, read the difference, learn whether that person has an account. Same for magic-link
sends — an unknown address must produce a response indistinguishable from a real send.

---

## 10. Keys and environment

| Variable | Where it lives | Notes |
|---|---|---|
| `NEXT_PUBLIC_CHALLENGE_SITE_KEY_CONTACT` | Client bundle | Public by design — it is in the page source |
| `CHALLENGE_SECRET_CONTACT` | API env only | Never in the client, never in a log, never in a doc |
| `APP_PROXY_SECRET` | Proxy env + API env | Must match on both sides |

**Use separate widget pairs for separate surfaces.** One pair for the contact form, another
for authentication, another for privacy requests. Cloudflare's dashboard gives each widget
its own analytics, so you can see which surface is being hit, and a key rotation on one
surface does not take down the others.

**Env var must exist before the code that reads it deploys.** This is a deploy-ordering rule
with real teeth: ship the variable, confirm it is present, then ship the code. Reversed, you
get a window where the surface is live and rejecting everything — and if you have followed
the fail-closed advice in this document, it will be rejecting *everything*, correctly and
invisibly, until someone complains.

**Reference secrets by location and rotation path, never by value.** In documentation, in
runbooks, in chat, in commit messages. "The contact widget's secret lives in the API
service's environment; rotate it in the vendor dashboard and update the variable" is a
complete and safe sentence.

---

## 11. Proving it works: the negative cases

A gate is worth exactly what its negative case can see. Every one of these must be
**observed failing**, by hand, at least once — not asserted in a comment, not assumed from
the code reading correctly.

1. **Submit with the honeypot filled.** Use the browser devtools to put text in the hidden
   field. Expect the generic 400. Confirm in logs that no challenge verification was
   attempted — that is the ordering working.
2. **Submit with a garbage token.** Replace the token in the request body. Expect 400.
3. **Submit with a *reused* token.** Send the same valid token twice. The second must fail —
   this proves you are verifying server-side rather than trusting the widget's presence.
4. **Unset the secret in a non-production environment.** Every submission must be refused,
   and the error log must name the variable. This is the fail-closed path, and it is the one
   nobody ever tests.
5. **Exceed the rate limit.** Expect 429 with a `Retry-After` header. Then confirm the count
   resets after the window.
6. **Exceed the rate limit from two different IPs.** Each must have its own bucket. **This is
   the test that catches the forwarded-IP bug**, and nothing else catches it — with the bug
   present, the limiter looks perfectly healthy from a single machine.
7. **Submit a message containing `<script>alert(1)</script>` and a real URL.** Open the
   resulting email. The script must appear as visible text and the URL must be defanged.
8. **Leave the form open for longer than the token lifetime, then submit.** The widget must
   have re-solved by itself, or the submit button must be disabled. The user must never be
   able to send a stale token.
9. **Try to reach the API directly**, bypassing the proxy. Expect a 404, not a 403.
10. **Read your own logs afterwards.** Every refusal above should be distinguishable to you
    and indistinguishable to the caller. If you cannot tell from the logs which layer caught
    what, you have uniform refusal without observability, which is half the design.
11. **Run the refusals against the vendor's own test keys, so they are repeatable.**
    Cloudflare publishes dummy sitekeys and secrets that make the outcome deterministic
    instead of something you have to contrive: a sitekey that always passes, one that always
    fails, one that forces an interactive challenge, and — the useful one — a secret key
    (`3x0000000000000000000000000000000AA`) that answers "token already spent". That last one
    is how you exercise the replay path without waiting for a real token to be spent, which
    is otherwise one of the hardest cases to stage. Production secrets reject dummy tokens and
    the reverse, so this belongs in a test environment, not behind a flag in production.

    This is the bridge from watching a gate refuse by hand to watching it refuse on every
    commit. The philosophy does not change; only who is looking.

12. **Load the form with the stylesheet blocked, and look at it.** In devtools, disable the
    site's CSS — or block the request outright — and confirm the honeypot is still invisible.
    This is the only test that distinguishes a field hidden by something that always arrives
    from one hidden by something that usually does, and "usually" is the whole bug. Measure the
    element rather than trusting your eyes: read its position and size with the stylesheet
    off, and expect it off-screen and one pixel square. If it appears, your honeypot has a
    window every time you change your CSS.

---

## 12. Adoption order

If you are retrofitting an existing form, do it in this order. Each step is independently
valuable and independently shippable, and the order is by ratio of protection gained to
effort spent.

1. **Schema validation and a generic 400.** One afternoon. Closes the widest class of
   garbage and gives every later step a place to hang.
2. **Fixed recipient and output escaping.** One afternoon. Closes open relay and the
   phishing-your-own-staff path.
3. **Honeypot.** Twenty minutes. Catches a genuinely large fraction of naive bots for
   almost nothing.
4. **Rate limiting, per IP, per surface.** One day. Do the forwarded-IP work *in this step*
   — a limiter that cannot distinguish between people is not worth deploying.
5. **The challenge widget, verified server-side.** One to two days including the widget
   lifecycle work. Do it last because it is the most work, and because the previous four
   steps make it the only remaining gap.
6. **Uniform refusal.** An hour, once everything else exists. Collapse all the error paths
   to one response.
7. **Run the twelve negative cases in section 11.** Half a day. This is not optional: the
   preceding six steps are claims, and this step is the only thing that turns them into
   facts.

---

## 13. Known limits — state them, do not hide them

Honest documentation of what this pattern does *not* do is part of the pattern.

- **The in-memory limiter is single-instance.** Horizontal scaling multiplies the ceiling by
  the instance count, silently. Named trigger for moving to a shared store, written in the
  code.
- **A fixed window is not a sliding window.** A user can send `limit` requests at the end of
  one window and `limit` again at the start of the next. Adequate for abuse friction, not
  for precise quota enforcement.
- **The origin lock raises cost; it does not make extraction impossible.** It turns "one
  unauthenticated GET returns everything behind the API" into "drive a real browser through the
  bot-managed front door, session by session". Raising the cost is the goal. *Impossible* is
  not on the menu for public content.
- **The honeypot catches naive bots only.** A targeted attacker reads your DOM. It is a cheap
  filter, not a defence.
- **The challenge is a vendor dependency.** If they are down, your form is down — which is
  the deliberate consequence of failing closed, and the right trade.

---

## 14. The general forms worth carrying to the next project

Strip out the specifics and these are what remain — they apply well beyond forms.

**A defence that cannot be observed failing is not a defence.** The forwarded-IP bug is the
canonical case: the limiter ran, counted, and returned 429s, and had simply stopped
distinguishing between people. It looked healthy from every angle except the one test nobody
runs.

**A gate is worth exactly what its negative case can see.** If you have never watched a check
refuse something, you do not know that it refuses anything.

**Fail closed, and never add the "assume ok if the vendor is down" branch.** An outage that
blocks a form is visible and temporary. One that opens a form to bots is neither.

**Fail closed is half of it; fail bounded is the other half.** Closing covers the wrong
answer. It says nothing about no answer, which is the case that parks a handler on somebody
else's socket until a timeout you did not choose fires. Put a deadline on every call your own
response waits behind, and the unbounded wait becomes an ordinary failure the closed path
already handles.

**A retry of a request is not a retry of the thing the request was about.** Anything
single-use — a token, a charge, a one-shot job — needs the retry to carry its own identity, or
the second attempt is a second go at something that could only happen once, and the rejection
it earns looks exactly like an attack.

**Cheapest check first is a security decision, not a performance one.** Ordering is what
decides whether a stranger can make you spend money. A free string comparison ahead of a
paid outbound call means the dumbest traffic costs you nothing; the same checks in the other
order turn your own defences into the thing being exhausted.

**Storing input safely and rendering input safely are different problems, and solving the
first does not solve the second.** Store what they typed. Escape where it lands, which is a
question about the destination and not about the value. Anything that mangles on the way in
has lost data and still has to escape on the way out.

**A header your CDN owns is not a forwarding channel.** More generally: any field an
intermediary is entitled to rewrite is not a field you can use to carry meaning past it.

**Divergent error messages are a map of your defences.** You draw it and hand it over, one
probe at a time.

**A control whose correctness spans two separately cached artefacts is not one control.** It
is two, and it is only correct while they agree. Caching makes them disagree on a schedule
you do not set. Ask of any check: what has to arrive, from where, for this to be true? If the
answer names more than one thing, either bind them together — a content hash in the URL is
usually enough — or move the check somewhere that only needs one of them.

**A workaround that depends on a permission is a debt against whoever withdraws it.** Hiding
an element inline needs `'unsafe-inline'`; trusting a header needs whatever guarantees that
header. The person who later withdraws the permission is doing the right thing, will have no
idea what they broke, and will not find out from your code unless you wrote it down beside
the permission rather than beside the workaround.

**A citation in code names something safe to publish.** The reasoning beside the code is the
valuable part and it does not need a filename to work. Cite a public URL, a standard anyone
can look up, or nothing. Never a repository or vault path, an internal document name, or an
organisation the code's owner does not name in public. The people most likely to get this
wrong are the ones whose internal filenames are their clients' names.

**Rate-limit the thing the attacker cannot rotate.** IPs are cheap and rotatable. The target
address, the target account, the target resource — those are the keys that actually bound
the abuse.

**Four copies of a security check is four chances for one to drift**, and the drift that
matters is silent: a copy that stops checking still passes every test its own route has.

**A sentinel is not a value.** "Unknown" is a fine bucket key and a terrible thing to send to
someone else as fact.

---

## Licence and contributions

CC0 1.0: public domain, no attribution required, no strings. Use it, adapt it, ship it, sell
what you build with it. The warranty disclaimer is not
decoration: this is a description of what worked for one implementation, offered without any assurance
that it will work for you.

Corrections are more valuable than additions. If a trap here is wrong, out of date, or
specific to a topology in a way the text does not say, that is the thing worth reporting.

*The code is illustrative — read it for the reasoning in the comments, not as a library to
copy wholesale. There is deliberately no `reference/` folder of extracted files: two copies
of a security check is exactly the drift this document warns about in section 5, and a repo
that ignored its own advice would deserve the scepticism.*
