package fedtrust.resolver

import fedtrust.jwk.JwkSet
import fedtrust.types.{*, given}

/** A Trust Anchor as the relying party configures it: an Entity Identifier and
  * the public keys it signs with, obtained out of band.
  *
  * Section 10 requires this pairing: the party establishing trust "MUST have
  * ... a list of Entity Identifiers of Trust Anchors and their public signing
  * keys". Section 10.2 then requires the anchor's Entity Configuration to
  * verify "with a public key of the Trust Anchor" — these keys, not the `jwks`
  * inside the configuration itself.
  *
  * That distinction is the root of trust. An anchor's configuration is fetched
  * over the network, and a configuration verified only against its own `jwks`
  * proves nothing: anyone who can serve the anchor's well-known URL — through a
  * DNS hijack, a mis-issued certificate, or a compromised host — could sign one
  * with a key of their choosing.
  *
  * The pinned keys need not be every key the anchor publishes. Once its
  * configuration verifies under a pinned key, the `jwks` it carries are
  * authoritative for the statements it issues (section 10.2, `ES[i-1]` under
  * `ES[i]["jwks"]`). That is what lets an anchor roll its keys: it publishes
  * the new key in a configuration signed with the old one.
  */
final case class TrustAnchor(id: EntityId, jwks: JwkSet)
