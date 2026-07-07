# Why the prelude is trait-only

The [`prelude`](crate::prelude) re-exports **traits only**, and only anonymously
(`as _`). That is a deliberate design choice, not an oversight.

## Traits, because only traits have a discovery problem

A trait earns a place in the prelude if, and only if, users call its methods on
values they already hold. A method call like `grant.exchange(…)` gives no hint
which trait must be in scope for it to resolve — that is the one import problem a
prelude uniquely solves. Types don't have it: a type is named at its use site, so
an explicit `use` documents where it came from (and your IDE adds it for you).
The rule of thumb: **if you'd write its name in your code, import it yourself; if
you'd only call its methods, the prelude does it for you.** Traits you
*implement* rather than call are also excluded — an `impl` block names its trait
explicitly anyway.

## Anonymously, so it adds zero names

Every trait is imported `as _`, so `use huskarl::prelude::*` adds **no names** to
your namespace. It can never collide with your own types or another crate's
prelude, and it is always safe to grow: adding a trait to a future version cannot
break your code, because the glob import never introduces a name you could have
shadowed.
