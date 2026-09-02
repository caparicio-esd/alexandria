# Architecture decision records

A record per decision that was expensive to make and would be expensive to
reverse. Not a design document, not a changelog: each one states what was
decided, what it costs, and what would have to be true to decide otherwise.

They are written after the fact, from what the code and the git history already
show. A decision that left no trace in either does not need a record.

| | Decision | Status |
|---|---|---|
| [0001](0001-bounded-contexts-as-in-process-modules.md) | Bounded contexts are in-process modules, not services | Accepted |
| [0002](0002-one-configuration-document.md) | One configuration document, overridden from the environment | Accepted |
| [0003](0003-key-material-lives-in-an-external-wallet.md) | Key material lives in an external wallet | Accepted |
| [0004](0004-authentication-terminated-at-the-node.md) | Authentication is terminated at the node, not at the client | Accepted |
| [0005](0005-tls-terminated-by-a-proxy-in-development-too.md) | TLS is terminated by a proxy, in development too | Accepted |
| [0006](0006-one-image-three-deployment-shapes.md) | One image, three deployment shapes | Accepted |

## Writing one

Copy [template.md](template.md). Number it in sequence and add a row above.

Status is `Proposed`, `Accepted`, `Superseded by NNNN` or `Deprecated`. A record
is never edited to say something different once accepted — it is superseded by a
later one, and the earlier one keeps its text, because what makes these useful
in a year is being able to read what was believed at the time.
