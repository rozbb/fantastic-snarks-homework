# Burning money in zero knowledge

In this project we will build a system for provably burning monetary notes in a public ledger _without_ revealing which note you're burning.

Our goal is to familiarize ourselves with the workflow of writing zero-knowledge proofs in the [arkworks](https://github.com/arkworks-rs/) ecosystem. We will learn how to build zero-knowledge circuits, prove openings to cryptographic commitments, and prove membership in a Merkle tree. The purpose of this exercise is to make you feel comfortable playing with new ideas in arkworks. It is a massive framework, with lots of features, as well as weird sharp corners, so jumping right in might just be the best way to get started.

# Using Rust

If you are new to Rust, check out [this meta-guide](https://gist.github.com/noxasaxon/7bf5ebf930e281529161e51cd221cf8a). The most important thing to do first is the "Getting Started + Installation" Beyond this, I don't have a specific recommendation of tutorial, so I recommend you pick whatever suits your current comfort level and play with that. I'm looking for feedback here, so keep in mind what tutorials you tried and liked as well as disliked.

We strongly encourage you to use an IDE for this project. Whatever IDE you pick (e.g., Visual Code, Sublime, Neovim, Emacs), we recommend the following add-ons

* Language Server Protocol (LSP) — This lets you work directly with the semantics of a language. Arkworks is not the best documented library, and sometimes it is easiest to just use LSP to jump to the definition of a `struct` in order to find out what methods it exposes. Note some IDEs come with this built in, though they may require a specific installation to support Rust.
* `rust-analyzer` — This will show you errors in the source code itself, which will save you from having to go back and forth between your editor and your `cargo test` output

# Cryptographic preliminaries

A quick overview of the cryptographic components we use.

1. We model our public ledger as a Merkle tree. See [here](https://pangea.cloud/docs/audit/merkle-trees) for a short overview on Merkle trees and tree membership proofs (aka _authentication paths_).
2. The leaves of our Merkle tree are _cryptographic commitments_. We denote by `c = Com(val; nonce)` a commitment to the value `val`, using the _nonce_ (aka randomness) `nonce`. We say that `(val, nonce)` is the _opening_ of `c`. In order to be secure, a commitment scheme must be:
    * Binding - This means that a commitment cannot be opened to a different value other than what was originally committed to. Concretely, if `c = Com(val; nonce)` for some `val, nonce`, and someone produces `val', nonce'` such that `c = Com(val'; nonce')`, then it must be the case that `val' = val` and `nonce' = nonce`.
    * Hiding - This means that a commitment should say nothing about what is committed. In other words, for any choices of `val, val'` it should be impossible for an adversary to tell whether a given commitment `c` commits to `val` or `val'` (assuming the nonce is uniformly sampled).

An example of a secure commitment scheme is `Com(val; nonce) = Hash(nonce || val)` where `Hash` is a cryptographically secure hash function with certain properties (i.e., it is not vulnerable to length extension; so pick anything besides MD5, SHA-1, SHA-256 or SHA-512).

# Intro

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

Now suppose every note is a collector's item. They are quite rare. Lloyd's of Linden (a New Jersey-based "insurance" company) is giving out a certificate of authenticity to anyone who can prove possession of a note. Lloyd's says that a user "possesses" a note if they can prove that they know the note's opening and that that note is in the Merkle tree. This has two issues.

The first issue is privacy. Obviously, simply revealing this information outright would leak both the position of the note in the tree (ie when the user got the note) and the amount contained in the note. Neither of these are strictly necessary for Lloyd's to know. The solution here is to instead use a zero-knowledge proof: "I know an `amount`, `serial_num`, and `nonce` such that `Com((amount, serial_num); nonce)` appears in the Merkle tree."

The second issue is double-counting. Currently, there's no way for Lloyd's to tell if someone sent them 100 proofs for the same exact card. It should be the case that every card gets at most 1 certificate of authenticity. The solution here is to force a user to reveal the serial number when presenting a proof of membership. In other words, the zero-knowledge proof statement is now "I know an `amount` and `nonce` such that `Com((amount, serial_num); nonce)` appears in the Merkle tree", where `serial_num` is known to both the prover and verifier.

Our final proof statement has two steps: proving knowledge of an opening to a commitment, and proving membership in a Merkle tree. We will step through how each of these works in the arkworks zero-knowledge proof ecosystem.

# Getting started with arkworks

Let's start by taking a look at a "native" version of the computation we want to perform. Let's go to `src/lib.rs` and look at the code example in `test_merkle_tree`.

In this example, we create a bunch of random notes, and then make those leaves in a Merkle tree (using a Pedersen hash function). We then check that a claimed path for some leaf corresponds to a given root.

Our goal is to do some of this, and more, in zero-knowledge.

# Assignment

A partial implementation of our statement above is given in `src/constraints.rs` in the `BurnCircuit::generate_constraints` method. Of the three tests in that file, currently 2 fail. Go ahead and run `cargo test` to see the failures.

There's plenty of other files in `src/` as well. Peak around and see what they're doing. Hopefully the comments, as well as your code-jumping IDE will give you an idea of what's happening. For example `src/lib.rs` has a nice native code example in `test_merkle_tree`. In this example, we create a bunch of random notes, and then make those leaves in a Merkle tree (using a Pedersen hash function). We then check that a claimed path for some leaf corresponds to a given root. In this assignment we will do this, and more, in zero-knowledge.

The first two problems will require you to add some code to `BurnCircuit::generate_constraints`.

## Problem 1: Proving commitment opening in ZK

Currently, the `note_soundness` test fails. This test checks that `BurnCircuit` actually proves knowledge of the opening to the note commitment. Concretely, it checks that `BurnCircuit` is not satisfied if you give it any random opening to a note commitment. The reason the test currently fails is because no commitment opening check is performed in `gneerate_constraints`.

Write below `CHECK #1` a few lines of code that enforce the equality that the claimed note commitment equals the commitment of the secret note inputs. The file will have more detail on how to do this. Ensure that the `note_soundness` test passes.

## Problem 2: Proving Merkle tree membership in ZK

Currently, the `tree_soundness` test fails. This test checks that `BurnCircuit` actually proves that the claimed note commitment appears in the Merkle tree. Concretely, it checks that `BurnCircuit` is not satisfied if you give it any random Merkle root. The reason the test currently fails is because no tree membership check is performed in `generate_constraints`.

Write below `CHECK #2` a few lines of code that enforce leaf membership in the Merkle tree. The file will have more detail on how to do this. Ensure that the `tree_soundness` test passes.

## Problem 3: Groth16 proofs

Up until now we've just been symbolically executing the circuits. In reality, we want users to compute their proof and give it, along with their nullifier, to Lloyd's. This involves a few steps:

1. Lloyd's will generate the CRS for `BurnCircuit`, and their Pedersen hash constants, and publish both.
2. Users will prove ownership of their note and send the proof and commitment back to Lloyd's.
3. Lloyd's will check the proofs with respect to the public input

For the sake of simplicity, we will assume everyone has a copy of the same Merkle tree, which we generate in TODO

For each of the steps above, we have defined an executable file in the `src/bin/` directory. To run the binary, do `cargo run --release --bin BINARYNAME`. E.g., to run `src/bin/prove.rs` do `cargo run --release --bin prove`. 

Your job in this assignment is to

1. Fill out `bin/gen_params.rs`. This executable generates the Pedersen hash constants as well as the `BurnCircuit` CRS and put them in `pedersen_params.bin` and `burn_crs.bin`, respectively.
2. Fill out `bin/prove.rs`. This executable uses the above two files, as well as knowledge of a note, to create a Groth16 proof and output it and the circuit's public inputs to `proof.bin` and `pubinputs.bin`, respectively.
3. Fill out `bin/verify.rs`. This executable uses the above four files to verify the Groth16 proof.

Tip: if you remove the `--release` flag, proving will be slower, but it will also be easier to debug, as the proof compiler will be able to catch when you're trying to prove something that's false.

# Acknowledgements

This exercise was adapted from the [arkworks Merkle tree exercise](https://github.com/arkworks-rs/r1cs-tutorial/tree/5d3a9022fb6deade245505748fd661278e9c0ff9/merkle-tree-example), originally written by Pratyush Mishra.


---

# OLD CONTENT

```rust
let claimed_note_com_var = UInt8::new_input_vec(ns!(cs, "note com"), &self.leaf)?;
```


### Writing constraints to check Merkle tree paths

We'll be adding our constraints in `src/constraints.rs`, inside the function `generate_constraints`. Recall that our task is to check that the prover knows a valid membership path for a given leaf inside a Merkle tree with a given root.

We start by allocating the Merkle tree root `root` as a public input variable:
```rust
let claimed_root_var =
    <RootVar as AllocVar<MerkleRoot, _>>::new_input(ns!(cs, "root"), || Ok(&self.root))?;
```
Let's go over this incantation part-by-part.
* `RootVar` is a [type alias](https://doc.rust-lang.org/book/ch19-04-advanced-types.html#creating-type-synonyms-with-type-aliases) for the output of the hash function used in the Merkle tree.
* [`AllocVar`](https://docs.rs/ark-r1cs-std/0.4.0/ark_r1cs_std/alloc/trait.AllocVar.html) is a trait that describes how to allocate values for the circuit (ie as a circuit constant, as a public input, or as a private input).
* `new_input` is a method in `AllocVar` that reserves variables corresponding to the root. The variables are reserved as public inputs, as the root is a public input against which we'll check the private path.
    * The [`ns!`](https://docs.rs/ark-relations/0.4.0/ark_relations/macro.ns.html) macro enters a new namespace in the constraint system, with the aim of making it easier to identify failing constraints when debugging.
    * The closure `|| Ok(self.root)` provides an (optional) assignment to the variables reserved by `new_input`. The closure is invoked only if we need the assignment. For example, it is not invoked during SNARK setup.

We similarly allocate the note commitment as a public input variable, allocate the note amount and nonce as private input variables, and allocate the parameters of the hash as "constants" in the constraint system. This means that these parameters are "baked" into the constraint system when it is created, and changing these parameters would result in a different constraint system. Finally, we allocate the membership path as a private witness variable.

Now, we must  fill in the blanks by adding constraints to check the membership path. Go ahead and follow the hint in `constraints.rs` to complete this task.

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
