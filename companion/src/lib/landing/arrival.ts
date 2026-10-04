// What the landing page does with what it finds, kept out of the component so
// it can be stated and tested rather than inferred from a redirect.
//
// The case that forced this module out of `+page.svelte`: a signed-in browser
// whose crypto store the browser evicted. That used to `goto('/recover')`, and
// the recovery screen is a full page offering exactly one way forward — a
// 48-character key. An owner who does not have that key read it as a locked
// application and concluded they had to reset their identity and lose their
// history (#433).
//
// Neither was true. Only this page ever asks whether the store exists;
// approvals, every settings screen, mail triage and diagnostics do not, and
// all of them work untouched. So an evicted store is a **notice**, not a gate:
// the application opens, and the way to put the keys back is offered rather
// than imposed.

/** What the landing page should show. */
export type Arrival =
  /** No session on this browser: ask which deployment, as screen 1 always has. */
  | { kind: "form" }
  /**
   * A session this browser already holds. `keysGone` says the crypto store
   * is missing — which changes what is offered, and nothing about access.
   */
  | { kind: "signed-in"; owner: string; keysGone: boolean };

/**
 * `owner` is what `GET /api/session` answered, `hasKeys` whether the crypto
 * store is present. A Gateway that did not answer is `null`, and lands on the
 * form: the probe behind "Continue" will say so properly.
 */
export function arrivalFor(owner: string | null, hasKeys: boolean): Arrival {
  if (owner === null) {
    return { kind: "form" };
  }
  return { kind: "signed-in", owner, keysGone: !hasKeys };
}
