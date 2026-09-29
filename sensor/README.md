# sensor

The Sensor service (Rust): a Matrix client that decrypts portal-room events end-to-end, enriches them with contact and channel context, and publishes them as typed CloudEvents on the bus.

## Consent, and what reaches the bus

The Sensor never writes consent state — the Companion Gateway does, and the decisions reach the Sensor on the bus — but it decides what a published event contains, from the sender's current state ([ADR 0012](../docs/architecture/adr/0012-revoked-consent-reduces-publication.md)):

| Sender's consent | What the Sensor publishes |
| --- | --- |
| `granted` | The full event, contact `network_identifier` included. |
| `pending` | The same full event, labelled `pending`, minus the network identifier. The body **is** on the bus: consumers must refuse to process it. Unchanged by ADR 0012. |
| `revoked` | A **reduced** event: same deterministic id, network, consent label, both timestamps, room and sender references, reply and thread relations, attachments reduced to their shape — and no content. |

For a revoked sender, "no content" means: no `data.body`, no `reply_to.excerpt` and no reaction `target.excerpt` (an excerpt quotes a message, so it is content too — and the Sensor does not even fetch the quoted message), and inside each attachment no `mxc://` reference, no decryption material and no caption. What an attachment keeps is `kind`, `mime_type`, `size_bytes`, `dimensions` and `duration_ms`: they describe the message without carrying it. A filename is content — people name files `contrat-signé.pdf` — and the contract's attachment shape has none: for a media message a filename would only ever travel as the body or the caption, both dropped.

The table keys on the *sender*, which is right for every field an event carries except two. A reply's `reply_to.excerpt` and a reaction's `target.excerpt` quote a message **somebody else** wrote, and in a group that is routinely a different contact — so an excerpt published on the sender's label alone travels under a label that is not its author's, past the consumer gates that read that one label ([#110](https://github.com/linagora/twalk/issues/110)). Both decisions therefore have to be in the right state: an excerpt is published only when the sender's own state does not reduce publication **and** the author of the quoted message is `granted`. Anything short of a grant withholds it — an author the Sensor cannot resolve to a contact, a message it cannot fetch or decrypt, and `pending`, which in its consent cache is the absence of a decision rather than a weaker yes. The owner is the exception: the user's own messages, and the replies the Sensor sends for them, are quoted as they always were — there is no decision about the user to consult. Today that is the Sensor's own Matrix ID alone: the user's network ghosts still resolve as contacts, so a message they sent from their phone is quoted like anybody else's until [ADR 0018](../docs/architecture/adr/0018-the-users-own-messages-are-their-own-event-type.md) lands ([#109](https://github.com/linagora/twalk/issues/109)).

What is withheld is the quotation and never the event: the reaction keeps its emoji, the reply keeps the sender's own body, and both keep the reference to the message they point at. A reaction's `target.excerpt` is simply absent, which the contract allows unconditionally; a reply's `reply_to.excerpt` is present and **empty**, because the contract requires the field from any sender not `revoked` — the same empty excerpt the Sensor has always published for a parent it could not read.

So an operator can answer the two questions a revocation raises: the user keeps the evidence that a message arrived (a silent contact still looks different from a broken bridge), and nothing the contact sends is collected any more. Revocation applies to the future only — events already on the bus stay until retention expires, and erasing history is a separate, explicit action.

## Two identities: one observes, one acts

The Sensor holds **two** Matrix clients, and confusing them would undo most of what the rest of this document promises.

`@sensor:` is the one that **observes**. It syncs portal rooms, decrypts their events and publishes them, on the terms above. Its membership of a room is what the portal register reads as `observing` ([ADR 0024](../docs/architecture/adr/0024-a-portal-room-is-observed-by-invitation-per-conversation.md)), and nothing on this page changes for it.

The second is a device of the **owner's own account** (`SENSOR_OWNER_DEVICE_ACCESS_TOKEN` and `SENSOR_OWNER_DEVICE_ID`, [ADR 0025](../docs/architecture/adr/0025-twalk-acts-as-the-user-through-a-device-of-their-account.md), [#123](https://github.com/linagora/twalk/issues/123)), and it is the one that **acts**. It exists because a mautrix bridge relays to its network only what the logged-in user's own Matrix account sends: a reply from `@sensor:` is ignored, without a log line, so the outbound half of this product used to return an event id and deliver nothing. It is write-only — it joins portal rooms and posts approved replies, it registers no event handler, it publishes nothing on the bus, and it reads no history, which is why it needs neither cross-signing nor a recovery key. Its stores live in their own subdirectory of `SENSOR_STATE_DIR`, because a crypto store belongs to one device.

It joins **only** a room a bridge bot named in `SENSOR_BRIDGE_BOTS` invited it to. The inviter is the one authenticated fact in an invitation — the room id, the room's name and its `m.bridge` marker are all chosen by whoever sent it — and this device posts messages, so nothing else is enough.

Both halves are unset-by-default, and the degradation is stated rather than implied. With no owner device the Sensor says so once at startup, naming #123, and then says per reply what the reply reached:

| Posted by | Into | What the Sensor reports |
| --- | --- | --- |
| the owner's device | a portal room it has joined | `reach: contact` — the bridge relays it, because it really is the user's |
| `@sensor:` | a portal room | `reach: nobody` — the bridge ignores it and the contact receives nothing ([#216](https://github.com/linagora/twalk/issues/216)) |
| `@sensor:` | a room no bridge marked | `reach: contact` — native Matrix traffic ([ADR 0009](../docs/architecture/adr/0009-matrix-is-a-network.md)) has no bridge to ignore it |

The report is the approval event, unchanged, republished on `twalk.persona.reply.approved.v1.posted` with `reach` and `posted-as` headers — a sibling of the dead-letter subject, so no contract schema had to grow a field for it. It is published on every successful post and not only on the failures, because a signal that exists only in the bad case makes the good case a silence. The same answer is counted as `twalk_sensor_outbound_replies_total{reach}`.

When an owner device is configured and a reply targets a **portal** room it has not joined, nothing is posted: the send fails transiently, is retried, and ends on the dead-letter subject if the device never joins. Posting as `@sensor:` there would produce an event id and total silence, which is the outcome all of this exists to remove.

A fourth case, and the one ADR 0025's mitigation rests on: the owner **revokes** the device, from their phone or from any Matrix client, without asking anything here ([#229](https://github.com/linagora/twalk/issues/229)). The next thing asked of the homeserver under that token — the device's sync, or the send of a reply approved in the half-minute before that sync's long poll comes back — is refused with `M_UNKNOWN_TOKEN`, and the Sensor reads that for what it is rather than retrying it for ever: one `ERROR` naming `SENSOR_OWNER_DEVICE_ACCESS_TOKEN`, the script that replaces it and the fact that this is *not* a homeserver that is merely away; `twalk_sensor_owner_device_credential_gone 1`; the device's sync loop ended; and every reply to a **bridged** conversation refused rather than posted, transiently, so that re-provisioning inside the retry schedule still sends it and letting the schedule run out dead-letters it with that same sentence as its reason. A reply to a room **no bridge marked** is unaffected and still goes out as `@sensor:`, because there was never a bridge there to ignore it. `M_MISSING_TOKEN` is read as neither: a token this process failed to send is a bug here and not a decision of the owner's.

All four of those cases are things only this process knows, and until [#404](https://github.com/linagora/twalk/issues/404) it kept them to itself: the gauge renders on `/metrics`, the sentence goes to the log, and the Companion Gateway — which draws the approval screen — had no way to read either, so it went on offering a reply for a bridged conversation that this Sensor would refuse. The state now travels on the bus as `owner.device.state.changed.v1` ([ADR 0041](../docs/architecture/adr/0041-the-owner-device-says-on-the-bus-whether-it-can-act.md)): `present`, `credential_gone`, or `not_configured` on a deployment that was given no device at all. It is published at the start of **every** run, carrying the state this Sensor starts in, and then at each transition — a sync refused with `M_UNKNOWN_TOKEN`, a **send** refused with it (the half-minute window above, closed for the bus as well as for the gauge), and a handover arriving. The event names the device id for an operator comparing it with the owner's device list, never the token, and carries the remedy in the Sensor's own words, so the log, a dashboard and the approval screen tell one situation one way. It carries no `consent` extension and no `network`, so it is never a persona's trigger.

The acting device does not have to come from configuration, and on a deployment somebody onboarded it does not ([ADR 0034](../docs/architecture/adr/0034-the-users-device-credential-goes-from-browser-to-sensor-and-is-never-relayed.md), [#228](https://github.com/linagora/twalk/issues/228)). The owner's browser creates the device on their own account — an ordinary login named `twalk`, which appears in their device list and which they can revoke from any client — and hands its credential to this Sensor as an **Olm-encrypted to-device message**, so the Companion Gateway never receives one. What the Sensor does with it is four steps in an order where each makes the next one true: it **uses** it (the same two checks the configured path makes, on the account and on the device), **writes it down** in `SENSOR_STATE_DIR/owner-device.json` at `0600` — because the acknowledgement means *this deployment holds it*, and a credential only in memory is one the next restart loses — **acts through it** from that moment, which is what makes onboarding change anything without a restart, and only then **acknowledges** it with one state event in the handover room. Every way it can fail leaves the acknowledgement unwritten, and onboarding then reports a handover that did not happen rather than a device this deployment does not have. A handed-over credential wins over `SENSOR_OWNER_DEVICE_ACCESS_TOKEN`: it is the owner's own latest act and the remedy for the configured device having been revoked, and a deployment where configuration won could never be re-onboarded. The device it replaces is left alone — it is a device of their account like any other, and revoking it is theirs to do.

A credential is **refused** unless it arrived decrypted and from the device the owner offered it from, in a state event of the handover room only their account can write there; the expected device cannot be configuration, because it is minted by a login performed seconds earlier. Anybody on any homeserver can address a to-device event to this Sensor, so the refusals are counted as well as logged: `twalk_sensor_handovers_refused_total{why}` climbing with no onboarding in progress is somebody trying, and `twalk_sensor_handovers_held_total` is the counter that says onboarding worked. An event the Sensor cannot read at all — no Olm session for it, or a ciphertext that is not one — is counted as a refusal **only** while an offer stands, because that is the one situation in which a deployment is waiting for a credential that will not arrive; it is also what hardening the Sensor's trust requirement to `CrossSigned` would turn this whole channel into.


## The bus's retention policy

The `twalk` stream holds contacts' messages in cleartext — portal rooms are end-to-end encrypted, so the bus is the one place in a deployment where they exist at rest — and the Sensor is what decides how long ([ADR 0037](../docs/architecture/adr/0037-the-bus-keeps-ninety-days-and-two-gigabytes-and-no-more.md), [#174](https://github.com/linagora/twalk/issues/174)). `src/bus.rs` names every field of the stream's configuration; three are the operator's:

| Variable | Default | What it decides |
| --- | --- | --- |
| `SENSOR_BUS_MAX_AGE_DAYS` | `90` | How long an event is kept. Zero is refused: NATS reads it as "for ever", which is the undecided policy this replaced. |
| `SENSOR_BUS_MAX_BYTES` | `2147483648` (two GiB) | How large the stream may grow before the oldest events are discarded. Not the working limit — ninety days of a real account's traffic is nearer 90 MB — but the reason the user's disk is never the thing that gives way. |
| `SENSOR_BUS_DUPLICATE_WINDOW_SECONDS` | `86400` (a day) | How long the bus remembers a `Nats-Msg-Id`. A correctness setting: a restart re-syncs from Matrix and republishes, and under NATS's two-minute default a republished event reached every consumer twice. It cannot be longer than the age. |

The rest is fixed: `discard old`, `s2` compression, file storage, one replica, no count ceiling. At every start the Sensor creates the stream with the policy or **updates an existing one in place**, logging each field it changed (`max_age: 0s (for ever) → 7776000s (90d)`); shortening the age expires every event older than it at that moment. An update the bus refuses — a field JetStream cannot change on a live stream, such as its storage — is an `ERROR` naming the field and the two options, and the Sensor runs on the stream's existing policy: Twalk never deletes or recreates the stream, because expired events are gone for good and that is the operator's act. `tests/bus_policy.rs` asserts all of it on the bus's own `STREAM.INFO`.

## Tests

The integration tests (ticket 01) live in `tests/`. They boot a real Synapse and a real NATS JetStream via docker compose and verify behaviour at the process boundary; bots play the role of bridges over the Matrix client-server API.

What every component's suite shares — the test stack's lifecycle, the `Bus`, contract validation, `poll_until` — lives in the `twalk-test-harness` crate (`../tests/harness/`, ticket #20); `tests/harness/` keeps the Sensor's own half (the Matrix `Bot`, the portal helpers, `SensorProc`) and re-exports the crate, so test files see one flat `harness::` namespace.

```bash
cargo test   # boots the stack itself; ~15s cold, ~3s warm
```

Requires Docker and a Rust toolchain. The implementation lands from ticket 02 onwards (see `.scratch/sensor/issues/`).
