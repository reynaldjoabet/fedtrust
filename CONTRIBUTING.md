# Contributing

## Before opening a pull request

```
sbt scalafmtAll
sbt test
```

CI runs `scalafmtCheckAll`, the full test suite, and a compile of the
`examples` module.

## House rules

**Cite the specification.** This is an implementation of
[OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html).
Behaviour that the specification fixes should say which section fixes it, in a
comment at the point where a reader would otherwise wonder. Behaviour it leaves
open should say that too — the distinction matters when someone later has to
decide whether a change is a bug fix or a choice.

**Test against the specification, not against the code.** The strongest tests
in this repo reproduce worked examples from the specification itself: §6.1.5's
metadata policy example, Table 1 in §6.1.3.1.8, the `max_path_length` cases in
§6.2.1. A test that only asserts what the implementation already does will
survive the implementation being wrong.

**Keep `core` free of crypto and I/O.** It carries the data model and codecs.
Anything that signs, verifies, or reaches the network belongs further out. This
is what keeps `core` light and what would make a Scala.js build possible.

**Prefer an abstraction at a module boundary over a dependency across one.**
`EntityStatementFetcher` exists so that `resolver` never names an HTTP client.
New integration points should follow that shape: declare the port where it is
used, implement it in a module the user opts into.

## Adding a metadata policy operator

Federations may define their own operators (§6.1.3.2). An operator needs four
things stated explicitly, because the specification requires each of them:

1. Its application order relative to the standard operators — modifiers after
   `value`, checks before `essential`.
2. Which operators it may be combined with, and under what conditions.
3. How two of its values merge when superiors both use it, or that they cannot.
4. The JSON value types it supports, for both the operator and the parameter.

`PolicyOperator` carries the order; `Operators` carries the merge and apply
semantics; `Combinations` carries the pairings. All three need updating
together, and an unsupported operator named in `metadata_policy_crit` must fail
rather than be ignored.
