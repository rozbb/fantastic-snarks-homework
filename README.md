# Insuring baseball cards in zero-knowledge

In this project we will build a system for proving possession and details about a baseball card in a public purchase ledger _without_ revealing which card you're talking about. Yes this is silly. Extra credit for this homework is to find a better metaphor for the code I already have written.

Our goal is to familiarize ourselves with the workflow of writing zero-knowledge proofs in the [arkworks](https://github.com/arkworks-rs/) ecosystem. We will learn how to build zero-knowledge circuits, prove openings to cryptographic commitments, and prove membership in a Merkle tree. The purpose of this exercise is to make you feel comfortable playing with new ideas in arkworks. It is a massive framework, with lots of features, as well as weird sharp corners, so jumping right in might just be the best way to get started.

# Using Rust

[Install Rust.](https://www.rust-lang.org/learn/get-started)

If you are new to Rust, check out [this meta-guide](https://gist.github.com/noxasaxon/7bf5ebf930e281529161e51cd221cf8a). The most important thing to do first is the "Getting Started + Installation" Beyond this, I don't have a specific recommendation of tutorial, so I recommend you pick whatever suits your current comfort level and play with that. I'm looking for feedback here, so keep in mind what tutorials you tried and liked as well as disliked.

We strongly encourage you to use an IDE for this project. Whatever IDE you pick (e.g., Visual Code, Sublime, Neovim, Emacs), we recommend you install the `rust-analyzer` add-on. This will show you errors in the source code itself, which will save you from having to go back and forth between your editor and your `cargo test` output. It will also let you do language-level things like renaming variables, jumping to definitions, etc.

## Navigating code and documentation

The canonical documentation site for all Rust crates is [docs.rs](https://docs.rs). If it exists, the docs are on docs.rs. But Arkworks is not the best documented library, and sometimes it is easiest to just use your IDE to jump to the definition of a struct or a trait in order to find out what methods it exposes. This will be your superpower.

## Getting help

Rust has a very large online community, and there are tons of channels to get help. Very few people actually know anything about arkworks, so if you want answers, you should probably stick with language-level questions.

* [Rust Discord](https://discord.gg/rust-lang)
* [Rust Zulip](https://rust-lang.zulipchat.com/)
* Unofficial Rust Matrix Chat - `#rust:matrix.org`
* Unofficial Rust IRC - `##rust` on [LiberaChat](https://libera.chat/)

# Cryptographic preliminaries

A quick overview of the cryptographic components we use.

1. We model our public ledger as a Merkle tree. See [here](https://pangea.cloud/docs/audit/merkle-trees) for a short overview on Merkle trees and tree membership proofs (aka _authentication paths_).
2. The leaves of our Merkle tree are _cryptographic commitments_. We denote by `c = Com(val; nonce)` a commitment to the value `val`, using the _nonce_ (aka a random value) `nonce`. We say that `(val, nonce)` is the _opening_ of `c`. In order to be secure, a commitment scheme must be:
    * Binding - This means that a commitment cannot be opened to a different value other than what was originally committed to. Concretely, if `c = Com(val; nonce)` for some `val, nonce`, and someone produces `val', nonce'` such that `c = Com(val'; nonce')`, then it must be the case that `val' = val` and `nonce' = nonce`.
    * Hiding - This means that a commitment should say nothing about what is committed. In other words, for any choices of `val, val'` it should be impossible for an adversary to tell whether a given commitment `c` commits to `val` or `val'` (assuming the nonce is uniformly sampled).

An example of a secure commitment scheme is `Com(val; nonce) = Hash(nonce || val)` where `Hash` is a cryptographically secure hash function with certain properties (i.e., it is not vulnerable to length extension; so pick anything besides MD5, SHA-1, SHA-256 or SHA-512).

**TODO**:

  * what is a circuit
  * crs/proving key
  * constant
  * public input
  * private input ("witnesses")

# Intro

A baseball card is a tuple which contains `(purchase_price, serial_num)`, i.e., the dollar amount that the card was bought for, and the serial number printed on it. There is a public ledger, represented as a Merkle tree, whose leaves are all the known authentic baseball cards, appearing in order of time of purchase. In order to hide the potentially sensitive values of these cards, we make the leaves _card commitments_, i.e., values of the form `Com((purchase_price, serial_num); nonce)`.

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

Now suppose every card is a collector's item. They are quite rare. Lloyd's of Linden (a New Jersey-based "insurance" company) is giving out a certificate of authenticity to anyone who can prove possession of a card. According to Lloyd's a collector _possesses_ a card if and only if they can prove that they know the card commitment's opening, and that that commitment is in the Merkle tree. Proving this to Lloyd's has some complications, though.

The first issue is privacy. Obviously, simply revealing this information outright would leak both the position of the card in the tree (ie when the collector got the card) and the amount contained in the card. Neither of these are strictly necessary for Lloyd's to know. The solution here is to instead use a zero-knowledge proof: "I know an `amount`, `serial_num`, and `nonce` such that `Com((amount, serial_num); nonce)` appears in the Merkle tree."

The second issue (which is caused by our solution to the first issue) is double-counting. As stated, there's no way for Lloyd's to tell if someone sent them 50 proofs for the same exact card. It should be the case that every card gets at most 1 certificate of authenticity. The solution we will use is to force a collector to reveal the serial number when presenting a proof of membership. In other words, the zero-knowledge proof statement is now "I know an `amount` and `nonce` such that `Com((amount, serial_num); nonce)` appears in the Merkle tree", where `serial_num` is known to both the prover and verifier.

Our final proof statement has two steps: proving knowledge of an opening to a commitment, and proving membership in a Merkle tree. We will step through how each of these works in the arkworks zero-knowledge proof ecosystem.

# Assignment

A partial implementation of our statement above is given in `src/constraints.rs` in the `PossessionCircuit::generate_constraints` method. Of the three tests in that file, currently 2 fail. Go ahead and run `cargo test` to see the failures.

There's plenty of other files in `src/` as well. Peak around and see what they're doing. Hopefully the comments, as well as your code-jumping IDE will give you an idea of what's happening. For example `src/lib.rs` has a nice native code example in `test_merkle_tree`. In this example, we create a bunch of random cards, and then make those leaves in a Merkle tree (using a Pedersen hash function). We then check that a claimed path for some leaf corresponds to a given root. In this assignment we will do this, and more, in zero-knowledge.

The first two problems will require you to add some code to `PossessionCircuit::generate_constraints`.

## Problem 1: Proving commitment opening in ZK

Currently, the `card_soundness` test fails. This test checks that `PossessionCircuit` actually proves knowledge of the opening to the card commitment. Concretely, it checks that `BurnCircuit` is not satisfied if you give it any random opening to a card commitment. The reason the test currently fails is because no commitment opening check is performed in `gneerate_constraints`.

Write below `CHECK #1` a few lines of code that enforce the equality that the claimed card commitment equals the commitment of the secret card inputs. Ensure that the `card_soundness` test passes.

_Hint:_ Take a look at `src/card.rs`, and the [`EqGadget`](https://docs.rs/ark-r1cs-std/0.4.0/ark_r1cs_std/eq/trait.EqGadget.html) trait.

## Problem 2: Proving Merkle tree membership in ZK

Currently, the `tree_soundness` test fails. This test checks that `PossessionCircuit` actually proves that the claimed card commitment appears in the Merkle tree. Concretely, it checks that `BurnCircuit` is not satisfied if you give it any random Merkle root. The reason the test currently fails is because no tree membership check is performed in `generate_constraints`.

Write below `CHECK #2` a few lines of code that enforce leaf membership in the Merkle tree. Ensure that the `tree_soundness` test passes.

_Hint:_ take a look at [`PathVar`](https://github.com/arkworks-rs/crypto-primitives/blob/4b3bdac16443096b26426673bff409d4e78eec94/src/merkle_tree/constraints.rs).

## Problem 3: Groth16 proofs

Up until now we've just been symbolically executing the circuits. In reality, we want collectors to compute their proof and give it, along with their serial number, to Lloyd's. This involves a few steps:

1. Lloyd's will generate the proving key for `PossessionCircuit`, and their Pedersen hash constants, and publish both.
2. Collectors will prove ownership of their card and send the proof and commitment back to Lloyd's.
3. Lloyd's will check the proofs with respect to the public input

For the sake of simplicity, we will assume everyone has a copy of the same Merkle tree, which we generate in `src/util.rs`.

For each of the steps above, we have defined an executable file in the `src/bin/` directory. To run the binary, do `cargo run --release --bin BINARYNAME`. E.g., to run `src/bin/prove.rs` do `cargo run --release --bin prove`.

Your job in this assignment is to:

1. Fill in the portions of `bin/gen_params.rs` marked `todo!()`. This executable generates the Pedersen hash constants as well as the `PossessionCircuit` proving key and verifying key. It writes them to `pedersen_params.bin`, `possession_proving_key.bin`, and `possession_verifying_key.bin`, respectively.
2. Fill in the portions of  `bin/prove.rs` marked `todo!()`. This executable uses the above two files, as well as knowledge of a card, to create a Groth16 proof. It writes the proof and the card's serial number to to `possession_proof.bin` and `possession_revealed_serial.bin`, respectively.
3. Fill in the portions of `bin/verify.rs` marked `todo!()`. This executable uses the above files to verify the Groth16 proof.

Tip: if you remove the `--release` flag, proving will be slower, but it will also be easier to debug, as the proof compiler will be able to catch when you're trying to prove something that's false.

**TODO:** Snip out portions of these files

## Problem 4: Revealing purchase price

Lloyd's has changed their policy. They now require everyone to reveal the purchase price of their card.

1. Copy `src/constraints.rs` to a new file `src/constraints_showprice.rs`. Similarly, copy `src/bin/{gen_params.rs, prove.rs, verify.rs}` to `src/bin/{gen_params_showprice.rs, prove_showprice.rs, verify_showprice.rs}`. Also, make new filenames in `src/util.rs` like `POSSESSION_SHOWPRICE_PK_FILENAME` etc.
2. Modify `constraints_showprice::PossessionCircuit` to have `purchase_price` as a _public input_ rather than a private one.
3. Modify the remaining files to treat `purchase_price` as a public input value. Also use the new filenames so there's no accidental collision with the previously defined circuits. You can reuse Pedersen params.
4. Make sure that param generation, proving, and verification all succeed.

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

We similarly allocate the card commitment as a public input variable, allocate the card amount and nonce as private input variables, and allocate the parameters of the hash as "constants" in the constraint system. This means that these parameters are "baked" into the constraint system when it is created, and changing these parameters would result in a different constraint system. Finally, we allocate the membership path as a private witness variable.

Now, we must  fill in the blanks by adding constraints to check the membership path. Go ahead and follow the hint in `constraints.rs` to complete this task.
