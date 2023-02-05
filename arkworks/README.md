# Burning money in zero knowledge

In this project we will build a system for provably burning monetary notes in a public ledger _without_ revealing which note you're burning.

## Preliminaries

A quick overview of the cryptographic components we use.

1. We model our public ledger as a Merkle tree. See [here](https://pangea.cloud/docs/audit/merkle-trees) for a short overview on Merkle trees and tree membership proofs (aka _authentication paths_).
2. The leaves of our Merkle tree are _cryptographic commitments_. We denote by `Com(val; nonce)` a commitment to the value `val`, using the _nonce_ (aka randomness) `nonce`. In order to be secure, a commitment scheme must be:
    * Binding - This means that a commitment cannot be opened to a different value other than what was originally committed to. Concretely, if `c = Com(val; nonce)` for some `val, nonce`, and someone produces `val', nonce'` such that `c = Com(val'; nonce')`, then it must be the case that `val' = val` and `nonce' = nonce`.
    * Hiding - This means that a commitment should say nothing about what is committed. In other words, for any choices of `val, val'` it should be impossible for an adversary to tell whether a given commitment `c` commits to `val` or `val'` (assuming the nonce is uniformly sampled).

An example of a secure commitment scheme is `Com(val; nonce) = Hash(nonce || val)` where `Hash` is a cryptographically secure hash function with certain properties (i.e., it is not vulnerable to length extension; so pick anything besides MD5, SHA-1, SHA-256 or SHA-512).

## Setup

Let's describe a quirky payment system.

All value in our system is contained in _notes_. A note is simply a tuple which contains `(amount, serial_number)`. Since these are private values, we instead deal in _note commitments_, i.e., `Com((amount, serial_num); nonce)`.

```
      G = root
    /   \
  E      F
 / \    / \
A   B  C   D

where
    A = Com((amt1, serial1); nonce1)
    B = Com((amt2, serial2); nonce2)
    C = Com((amt3, serial3); nonce3)
    D = Com((amt4, serial4); nonce4)
```

Now suppose every note is a collector's item. They are quite rare. Being in possession of one is a big deal. We say a user "possesses" a note if they can prove to an external party that they know the note's opening and that that note is in the Merkle tree. Obviously, simply revealing this information outright would leak both the position of the note in the tree and the amount contained in the note. So we phrase it as a zero knowledge proof: "I know an `amount`, `serial_num`, and `nonce` such that `Com((amount, serial_num); nonce)` appears in the Merkle tree ."

We complicate things just a little bit more. We also care about double counting possession: a user shouldn't be able to claim to possess two notes in the tree when they only possess one. So we force a user to reveal the serial number when presenting a proof of membership. In other words, the proof is now "I know an `amount` and `nonce` such that `Com((amount, serial_num); nonce)` appears in the Merkle tree", where `serial_num` is known to both the prover and verifier.

This kind of proof requires two steps: proving knowledge of an opening to a commitment, and proving membership in a Merkle tree.

# Checking Merkle tree paths

In this example, our goal is to familiarize ourselves with the workflow of
writing constraints in `arkworks`. We do this by writing a simple constraint system
 that just verifies a single Merkle tree authentication path, using the APIs in
https://github.com/arkworks-rs/crypto-primitives/tree/main/src/merkle_tree.

We will learn how to:

* Allocate public and private variables in a circuit
* Invoke gadgets
* Invoke SNARKs on the final circuit

# Getting started

Let's start by taking a look at a "native" version of the computation we want to perform.
Let's go to [`src/lib.rs`](src/lib.rs) and look at the code example in `test_merkle_tree`.

In this example we create a Merkle tree using the Pedersen hash function, and then we check that a claimed path for some leaf corresponds to a given root.

Our goal is to replicate this check with constraints.

# Writing constraints to check Merkle tree paths

We'll be adding our constraints in [`src/constraints.rs`](src/constraints.rs), inside the function `generate_constraints`. Recall that our task is to check that the prover knows a valid membership path for a given leaf inside a Merkle tree with a given root.

We start by allocating the Merkle tree root `root` as a public input variable:
```rust
let root = RootVar::new_input(ark_relations::ns!(cs, "root_var"), || Ok(&self.root))?;
```
Let's go over this incantation part-by-part.
* `RootVar` is a [type alias](https://doc.rust-lang.org/book/ch19-04-advanced-types.html#creating-type-synonyms-with-type-aliases) for the output of the hash function used in the Merkle tree.
* `new_input` is a method on the [`AllocVar`](https://docs.rs/ark-r1cs-std/0.3.0/ark_r1cs_std/alloc/trait.AllocVar.html) trait that reserves variables corresponding to the root. The reserved variables are of the public input type, as the root is a public input against which we'll check the private path.
    * The [`ns!`](https://docs.rs/ark-relations/0.3.0/ark_relations/macro.ns.html) macro enters a new namespace in the constraint system, with the aim of making it easier to identify failing constraints when debugging.
    * The closure `|| Ok(self.root)` provides an (optional) assignment to the variables reserved by `new_input`. The closure is invoked only if we need the assignment. For example, it is not invoked during SNARK setup.

We similarly allocate the leaf as a public input variable, and allocate the parameters of the hash as "constants" in the constraint system. This means that these parameters are "baked" into the constraint system when it is created, and changing these parameters would result in a different constraint system. Finally, we allocate the membership path as a private witness variable.

Now, we must  fill in the blanks by adding constraints to check the membership path. Go ahead and follow the hint in `constraints.rs` to complete this task.

# Editing

We strongly encourage you to use an IDE for this project. Whatever IDE you pick (e.g., Visual Code, Sublime, Neovim, Emacs), we recommend the following add-ons

* Language Server Protocol (LSP) — This lets you work directly with the semantics of a language. Arkworks is not the best documented library, and sometimes it is easiest to just use LSP to jump to the definition of a `struct` in order to find out what methods it exposes. Note some IDEs come with this built in, though they may require a specific installation to support Rust.
* `rust-analyzer` — This will show you errors in the source code itself, which will save you from having to go back and forth between your editor and your `cargo test` output

# Testing our constraints

Once we've written our path-checking constraints, we have to check that the resulting constraint system satisfies two properties: that it accepts a valid membership path, and that it rejects an invalid path. We perform these checks via two tests: `merkle_tree_constraints_correctness` and `merkle_tree_constraints_soundness`. Go ahead and look at those for an example of how to test constraint systems in practice.

To run tests, use `cargo test`

ZK BURN
Burn a note. Can't burn it twice


what is a circuit
constant
public input
private input ("witnesses")


* WHAT IS A COMMITMENT


# Assignments

1. Fill in the details in X
2. Make a version of a ZK burn that also reveals the amount in your note
3. Why is the merkle authentication path private??
