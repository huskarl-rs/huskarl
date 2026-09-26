# Why the prelude is trait-only

The [`prelude`](crate::prelude) imports traits anonymously (`as _`) so their
methods are available on values you already hold. For example,
`grant.exchange(…)` requires a trait in scope even though the call does not
name that trait.

Types remain explicit imports: their names appear at the use site, making it
clear which import is needed. Traits primarily used in `impl` blocks are also
imported explicitly.

Anonymous imports avoid introducing trait names that could clash with your
own names. They still affect method resolution: two traits with the same
method name can make a call ambiguous. Adding a trait to the prelude therefore
still needs a compatibility review.
