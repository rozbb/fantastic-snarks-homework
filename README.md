# Insuring baseball cards in zero-knowledge

In this project we will build a system for proving possession and details about a baseball card in a public purchase ledger _without_ revealing which card you're talking about. Yes this is silly. Extra credit for this homework is to find a better metaphor for the code I already have written.

Our goal is to familiarize ourselves with the workflow of writing zero-knowledge proofs in the [arkworks](https://github.com/arkworks-rs/) ecosystem. We will learn how to build zero-knowledge circuits, prove openings to cryptographic commitments, and prove membership in a Merkle tree. The purpose of this exercise is to make you feel comfortable playing with new ideas in arkworks. It is a massive framework, with lots of features, as well as weird sharp corners, so jumping right in might just be the best way to get started.

# Using Rust

[Install Rust.](https://www.rust-lang.org/learn/get-started)

If you're familiar with other languages and want a crash course in Rust, I like [this](https://fasterthanli.me/articles/a-half-hour-to-learn-rust) tutorial. Beyond this, I don't have specific recommendations. This [meta-guide](https://gist.github.com/noxasaxon/7bf5ebf930e281529161e51cd221cf8a) has lots of resources for people of all incoming skill levels. Pick whatever suits your current comfort level and play with that. I'm looking for feedback here, so keep in mind what tutorials you tried and liked and disliked.

For this assignment, it will be helpful to be comfortable with:

* The [`Result`](https://doc.rust-lang.org/stable/rust-by-example/error/result.html) type (including `unwrap()` and the `?` operator)
* [Structs](https://doc.rust-lang.org/book/ch05-01-defining-structs.html)
* [Traits](https://doc.rust-lang.org/book/ch10-02-traits.html)

We strongly encourage you to use an IDE for this project. Whatever IDE you pick (e.g., Visual Code, Sublime, Neovim, Emacs), we recommend you install the `rust-analyzer` add-on. This will show you errors in the source code itself, which will save you from having to go back and forth between your editor and your `cargo test` output. It will also let you do language-level things like renaming variables, jumping to definitions, etc.

## Navigating code and documentation

The canonical documentation site for all Rust crates is [docs.rs](https://docs.rs). If it exists, the docs are on docs.rs. But Arkworks is not the best documented library, and sometimes it is easiest to just use your IDE to jump to the definition of a struct or a trait in order to find out what methods it exposes. This will be your superpower.

## Getting help

Rust has a very large online community, and there are tons of channels to get help. Very few people actually know anything about Arkworks, so if you want answers, you should probably stick with language-level questions.

* [Rust Discord](https://discord.gg/rust-lang)
* [Rust Zulip](https://rust-lang.zulipchat.com/)
* Unofficial Rust Matrix Chat - `#rust:matrix.org`
* Unofficial Rust IRC - `##rust` on [LiberaChat](https://libera.chat/)

Standard messaging etiquette applies:

1. Do not ask to ask a question. Just ask.
2. State your problem as clearly as possible. Ideally, reduce your problem to a minimum failing testcase, ie a small snippet of valid code that exemplifies your problem, and fails in the same way your real code fails. The [Rust Playground](https://play.rust-lang.org) is a nice place to to construct a minimum failing testcase and share a link to.
3. Do not spam the channel. It may take a while to get an answer. If it has been a long time since you asked and you've gotten no response, a single "bump" message is appropriate.

Note: If you are reading this again because you are hitting a problem, at this point you may wish this assignment was not in Rust. The alternative was one of a few special purpose language for SNARKs. They are slightly simpler. But there is no community to ask for help at all.

# Cryptographic preliminaries

A quick overview of the cryptographic components we use.

1. We model our public ledger as a Merkle tree. See [here](https://pangea.cloud/docs/audit/merkle-trees) for a short overview on Merkle trees and tree membership proofs (aka _authentication paths_).
2. The leaves of our Merkle tree are _cryptographic commitments_. We denote by `c = Com(val; com_rand)` a commitment to the value `val`, using the _commitment randomness_ `com_rand`. We say that `(val, com_rand)` is the _opening_ of `c`. In order to be secure, a commitment scheme must be:
    * Binding - This means that a commitment cannot be opened to a different value other than what was originally committed to. Concretely, if `c = Com(val; com_rand)` for some `val, com_rand`, and someone produces `val', com_rand'` such that `c = Com(val'; com_rand')`, then it must be the case that `val' = val` and `com_rand' = com_rand`.
    * Hiding - This means that a commitment should say nothing about what is committed. In other words, for any choices of `val, val'` it should be impossible for an adversary to tell whether a given commitment `c` commits to `val` or `val'` (assuming the com_rand is sampled uniformly).

An example of a secure commitment scheme is `Com(val; com_rand) = Hash(com_rand || val)` where `Hash` is a cryptographically secure hash function with certain properties (i.e., it is not vulnerable to length extension; so pick anything besides MD5, SHA-1, SHA-256 or SHA-512).


Recall that the proof systems we use take an arithmetic circuit representing a computation that has private inputs (AKA the witness) and public inputs. 
Some inputs will be constans, i.e., fixed by the circuit.  For Groth16, there is a circuit specific proving key (aka evaluation key) used by the prover and a circuit specific verification key. Your task is to assemble circuits that realize commitments, merkle trees, etc into a particular application.


# Intro
In this assignment, you will build a toy zcash-esque scheme for manipulating commitments in a Merkle tree. In this case, the objects will be baseball cards.

A baseball card is a tuple which contains `(purchase_price, serial_num)`, i.e., the dollar amount that the card was bought for, and the serial number printed on it. There is a public ledger, represented as a Merkle tree, whose leaves are all the known authentic baseball cards, appearing in order of time of purchase. In order to hide the potentially sensitive values of these cards, we make the leaves _card commitments_, i.e., values of the form `Com((purchase_price, serial_num); com_rand)`.

```
      G = root
    /   \
  E      F
 / \    / \
A   B  C   D

where
    A = Com((amt1, serial1); com_rand1)
    B = Com((amt2, serial2); com_rand2)
    C = Com((amt3, serial3); com_rand3)
    D = Com((amt4, serial4); com_rand4)
```

Now suppose every card is a collector's item. They are quite rare. Lloyd's of Linden (a New Jersey-based "insurance" company) is giving out a certificate of authenticity to anyone who can prove possession of a card. According to Lloyd's a collector _possesses_ a card if and only if they can prove that they know the card commitment's opening, and that that commitment is in the Merkle tree. Proving this to Lloyd's has some complications, though.

The first issue is privacy. Obviously, simply revealing this information outright would leak both the position of the card in the tree (ie when the collector got the card) and the amount contained in the card. Neither of these are strictly necessary for Lloyd's to know. The solution here is to instead use a zero-knowledge proof: "I know an `amount`, `serial_num`, and `com_rand` such that `Com((amount, serial_num); com_rand)` appears in the Merkle tree."

The second issue (which is caused by our solution to the first issue) is double-counting. As stated, there's no way for Lloyd's to tell if someone sent them 50 proofs for the same exact card. It should be the case that every card gets at most 1 certificate of authenticity. The solution we will use is to force a collector to reveal the serial number when presenting a proof of membership. In other words, the zero-knowledge proof statement is now "I know an `amount` and `com_rand` such that `Com((amount, serial_num); com_rand)` appears in the Merkle tree", where `serial_num` is known to both the prover and verifier.

Our final proof statement has two steps: proving knowledge of an opening to a commitment, and proving membership in a Merkle tree. We will step through how each of these works in the Arkworks zero-knowledge proof ecosystem.

# Assignment

A partial implementation of our statement above is given in `src/constraints.rs` in the `PossessionCircuit::generate_constraints` method. Of the three tests in that file, currently 2 fail. Go ahead and run `cargo test` to see the failures.

There's plenty of other files in `src/` as well. Peak around and see what they're doing. Hopefully the comments, as well as your code-jumping IDE will give you an idea of what's happening. For example `src/lib.rs` has a nice native code example in `test_merkle_tree`. In this example, we create a bunch of random cards, and then make those leaves in a Merkle tree (using a Pedersen hash function). We then check that a claimed path for some leaf corresponds to a given root. In this assignment we will do this, and more, in zero-knowledge.

The first two problems will require you to add some code to the `PossessionCircuit::generate_constraints` method.

## How to submit

Once you've done the problems (and optional extra credit), you will **submit your homework by zipping the `src/` folder and uploading the zip file to ELMS.** I should be able to unzip your submission into a fresh repo, and run `cargo test` and all the `cargo run` commands to check that everything is correct.

**Do NOT zip the entire assignment folder.** I do not want 40MB of garbage partial build files.

## Problem 1: Proving commitment opening in ZK

Currently, the `card_soundness` test fails. This test checks that `PossessionCircuit` actually proves knowledge of the opening to the card commitment. Concretely, it checks that `PossessionCircuit` is not satisfied if you give it any random opening to a card commitment. The reason the test currently fails is because no commitment opening check is performed in `gneerate_constraints`.

Fill in the `todo!()`s below `CHECK #1`. This code should:

1. compute the commitment of `card_var`,
2. enforce that the resulting commitment equals the claimed commitment.

Once this is done, ensure the `card_soundness` test passes.

_Hint 1:_ `card_var` already has a way of computing the commitment. Look at `src/card.rs`.

_Hint 2:_ You need the circuit to enforce that two things are equal. Take a look at the [`EqGadget::enforce_equal`](https://docs.rs/ark-r1cs-std/0.4.0/ark_r1cs_std/eq/trait.EqGadget.html#method.enforce_equal). Most types we care about implement `EqGadget`.

## Problem 2: Proving Merkle tree membership in ZK

Currently, the `tree_soundness` test fails. This test checks that `PossessionCircuit` actually proves that the claimed card commitment appears in the Merkle tree. Concretely, it checks that `PossessionCircuit` is not satisfied if you give it any random Merkle root. The reason the test currently fails is because no tree membership check is performed in `generate_constraints`.

Fill in the `todo!()`s below `CHECK #2`. This code should:

1. compute the root node of the Merkle authentication path,
2. enforce that the resulting value equals the publicly known Merkle root.

Once this is done, ensure the `tree_soundness` test passes.

_Hint:_ `auth_path_var` already has a way of computing the root. See [`here`](https://github.com/arkworks-rs/crypto-primitives/blob/4b3bdac16443096b26426673bff409d4e78eec94/src/merkle_tree/constraints.rs#L191).

## Problem 3: Groth16 proofs

Up until now we've just been symbolically executing the circuits. In reality, we want collectors to compute their proof and give it, along with their serial number, to Lloyd's. This involves a few steps:

1. Lloyd's will generate the proving key for `PossessionCircuit`, and their Pedersen hash constants, and publish both.
2. Collectors will prove ownership of their card and send the proof and commitment back to Lloyd's.
3. Lloyd's will check the proofs with respect to the public input

This will correspond to our files in the `src/bin/` directory. Specifically:

* `src/bin/gen_params.rs` — This will generate the hashing parameters as well as the proving and verifying key of our circuit. It will write these to `pedersen_params.bin`, `possession_proving_key.bin`, and `possession_verifying_key`, respectively.
* `src/bin/prove.rs` — This will use the above data, plus some secret knowledge about a card and its position in the Merkle tree, to create a Groth16 proof. It writes the proof and the card's serial number to `possession_proof.bin` and `possession_revealed_serial.bin`, respectively.
* `src/bin/verify.rs` — This will use the revealed serial number public knowledge of a Merkle root to verify the Groth16 proof computed above.

For the sake of simplicity, we have hard-coded a Merkle tree in `src/util.rs`.
**We will assume everyone has a copy of the same Merkle tree.**
The Merkle root, which we will pass to the prover and verifier, is represented in base32 as `f5pj64oh3m6anguhjb5rhfugwe44ximao17ya3wgx1fbmg1iobmo`.

### Problem 3.1: Generate params

The first step to deploying a proof system is to generate all the public values. This is includes: the details of the hash function we're using, the Groth16 proving key, and the Groth16 verifying key.
Generating the Groth16 proving/verifying keys of a circuit is a little bit easier than actually proving something. You're not proving anything yet, you're just defining the structure of the proof.
So, in `gen_params.rs`, rather than constructing a circuit which is actually satisfied, we only need to construct a circuit _with the same shape_ as the circuit we want satisfied. Concretely, this means that we can take a `PossessionCircuit` and fill it with arbitrary values, so long as they have right type/size as the values we want to use. Note: we still must give it the correct constants, because those values are baked into the circuit and cannot change in the future.

Your task is to make up some arbitrary values and stick them into the `PossessionCircuit` definition in `src/bin/gen_params.rs` in the appropriate place. These locations are marked with `todo!()`. Once you're done, the following command should succeed:
```
cargo run --release --bin gen_params
```
This will panic and abort until all `todo!()`s are filled in.

Tip: if you remove the `--release` flag, proving will be slower, but it will also be easier to debug, as the proof compiler will be able to catch when you're trying to prove something that's false.

_Hint:_ The field element type `F` implements [`UniformRand`](https://docs.rs/ark-ff/0.3.0/ark_ff/trait.UniformRand.html#tymethod.rand). It also implements [`Default`](https://doc.rust-lang.org/nightly/core/default/trait.Default.html).

### Problem 3.2: Prove possession

This is the meat of the proof system. We must use the proving key, known public constants, and private inputs in order to generate a proof of possession of a baseball card. In this case, the private info ("witnesses") is the commitment randomness for committing to the card and the Merkle authentication path proving membership in the tree. The proof will also be accompanied by whatever public inputs are necessary. In this case, the prover is revealing the card's serial number. The proof will be saved in `possession_proof.bin` and the now-public serial will be saved in `possession_revealed_serial.bin`.

Your task is to fill in the `todo!()` items in `src/bin/prove.rs` in order to make the proving procedure succeed. There's only one line of computation here, and a few lines of filling in values. Remember, the things that go into the `PossessionCircuit` here are not like before: they MUST be values that make the circuit succeed. Once you're done, the following command should succeed:
```
cargo run --release --bin prove -- \
    pedersen_params.bin \
    possession_proving_key.bin \
    f5pj64oh3m6anguhjb5rhfugwe44ximao17ya3wgx1fbmg1iobmo
```
(note the `\` just tells your terminal that the command continues on the next line.)
If you want to check if you're proving an invalid statement, remove the `--release` flag. This will save you lots of headaches for the next problem. If you're trying to verify a false statement, you're gonna have a bad time.

_Hint:_ You will need to make a [Merkle authentication path](https://github.com/arkworks-rs/crypto-primitives/blob/4b3bdac16443096b26426673bff409d4e78eec94/src/merkle_tree/mod.rs#L338). You already have the `tree`.

_Note:_ Look at how `public_inputs` are generated in this file. Everything ends up being represented as field elements in order for our proof system to work. You'll have to change this line in the extra credit.

### Problem 3.3 Verify possession

The final step is for Lloyd's to verify the proofs that have been generated. Lloyd's verifier will use the known, public Merkle root and the claimed serial number in order to determine whether the Groth16 proof is valid.

Verification is probably the simplest of the steps. For this problem, just fill out the single `todo!()` in `src/bin/verify.rs. You will have to serialize the public input to field elements, just like the prover did. Once you're done, the following command should succeed, and output "Proof verified successfully":
```
cargo run --release --bin verify -- \
    possession_verifying_key.bin \
    possession_proof.bin \
    possession_revealed_serial.bin \
    f5pj64oh3m6anguhjb5rhfugwe44ximao17ya3wgx1fbmg1iobmo
```

_Hint:_ Look how `prove.rs` defined `public_inputs`.

## Problem 4: Revealing purchase price

Lloyd's has changed their policy. They now require everyone to reveal the purchase price of their card.

1. Copy `src/constraints.rs` to a new file `src/constraints_showprice.rs`. Similarly, copy `src/bin/{gen_params.rs, prove.rs, verify.rs}` to `src/bin/{gen_params_showprice.rs, prove_showprice.rs, verify_showprice.rs}`. Also, make new filenames in `src/util.rs` like `POSSESSION_SHOWPRICE_PK_FILENAME` etc.
2. Modify `constraints_showprice::PossessionCircuit` to have `purchase_price` as a _public input_ rather than a private one.
3. Modify the remaining files to treat `purchase_price` as a public input value. Also use the new filenames so there's no accidental collision with the previously defined circuits. You can reuse Pedersen params.
4. Make sure that param generation, proving, and verification all succeed.

# Acknowledgements

This exercise was adapted from the [arkworks Merkle tree exercise](https://github.com/arkworks-rs/r1cs-tutorial/tree/5d3a9022fb6deade245505748fd661278e9c0ff9/merkle-tree-example), originally written by Pratyush Mishra.
