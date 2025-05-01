---
title: "Exploiting the zkEVM: Uncovering Soundness and Composition Vulnerabilities in ZK Circuits"
seoTitle: "Exploiting zkRollups: Uncovering Vulnerabilities in the zkEVM"
seoDescription: "Circuit-Level Attacks: A Key Vector for Ethereum Layer 2 (zkRollups)"
datePublished: Thu May 01 2025 05:39:45 GMT+0000 (Coordinated Universal Time)
cuid: cma4xr00l000d09l5e5bzey7d
slug: exploiting-the-zkevm-uncovering-soundness-and-composition-vulnerabilities-in-zk-circuits
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1746077927376/910b6194-cd26-4571-8473-f90252796c8a.webp
ogImage: https://cdn.hashnode.com/res/hashnode/image/upload/v1746067044516/2ac93071-6ffc-4096-996c-9627aa31cfff.webp
tags: ai, javascript, python, security, machine-learning, typescript, bitcoin, cryptocurrency, ethereum, solidity, smart-contracts, defi, zkevm, zk-snark, zkrollup

---

### [**zkevm.dev**](https://zkevm.dev)

Lately, I’ve been diving deeper into [**Validity Proofs**](https://zkproof.org/about/?amp) and Zero-Knowledge (ZK) [circuits](https://tlu.tarilabs.com/cryptography/rank-1). It's fascinating stuff, especially with its relevance to scaling solutions like the [**zkEVM (zkRollups)**](https://scroll.io/blog/zkevm). I wanted to jot down some thoughts, examples, and potential vulnerabilities / attack vectors – partly notes for myself, partly sharing my research. The core idea is proving a computation happened correctly, often without revealing *all* the inputs, which is key for both privacy and scalability.

---

## The Basics: Sorting Numbers (From Code to Constraints)

Let's start with a familiar task: sorting three numbers, `A`, `B`, `C`.

In Python, it's procedural:

```python
# Assume A, B, C are defined
if A > B:
  A, B = B, A
if A > C:
  A, C = C, A
if B > C:
  B, C = C, B

# Now A, B, C are sorted
print(A, B, C)
```

This code *executes* the sort.

Now, think about proving this sort happened correctly using a ZK circuit, similar to how computations are verified in various [Ethereum Layer 2 networks](https://decrypt.co/resources/what-is-zkevm?amp=1). We shift from *how* to sort to *enforcing properties* of the result.

```plaintext
// Circuit: SortVerifier
input: A, B, C // Public inputs

// Witness: A', B', C' (Provided by the ZK prover)
// These represent the claimed sorted output

// Constraint 1: Permutation Check
// Ensures the output contains the same elements as the input
enforce({A', B', C'} is a permutation of {A, B, C})

// Constraint 2: Ordering Check
// Ensures the output is actually sorted
enforce(A' <= B')
enforce(B' <= C')

output: A', B', C' // The claimed sorted values
```

The key difference? The circuit defines *constraints*. These `enforce` statements are the heart of it – they get compiled down into polynomial equations or other mathematical forms that the underlying [ZK-SNARK](https://docs.gnark.consensys.io/Concepts/zkp) or [ZK-STARK](https://docs.starknet.io/) system uses. The *prover* finds the **witness** values (`A'`, `B'`, `C'`) that satisfy these constraints and generates a compact ZK proof. The *verifier* (e.g., a smart contract on L1 for a zkEVM rollup) just needs to check this proof against the public inputs and the [circuit](https://tlu.tarilabs.com/cryptography/r1cs-bulletproofs/mainreport.html#arithmetic-circuits) definition, without re-executing the sort.

Our goal is to design constraints such that:

1. Valid executions *always* satisfy all constraints (allowing a proof).
    
2. Invalid executions can *never* satisfy all constraints (preventing a proof).
    

---

## A More Involved Example: Data Validation in ZK

Let's apply this to data validation. Imagine validating a data structure `h` composed of 'B' and 'V' elements (*max 5 of each, maybe zero*).

**Step 1: Decomposition Circuit**

Break down `h` – the prover provides the components as witness data.

```plaintext
// Circuit: Decomposer
input: data_structure h // Public input

// Witness: B[], V[] (Private data provided by prover)
output: elements_B B[], elements_V V[]

// Constraint: h must be composed *only* from the provided B and V arrays
enforce(h is composed from B[] and V[]) // Constraint on inputs & witness
```

**Step 2: Element Validation Circuit (Type B)**

Check each 'B' element against a property, say `is_valid(b)`. This involves state transitions, much like stepping through execution traces in a zkEVM.

```plaintext
// Circuit: CheckerB
input: elements_B B[] // Could be output from Decomposer

// Uses intermediate variables (part of the witness)
// Assume max 5 elements

for i in range(5) {
  // Intermediate witness: flag_i, current_b_i, remaining_B_i+1
  // State B_i transitions to B_i+1

  // Constraint: Set flag based on whether B_i is non-empty
  enforce(if B_i is nonempty then flag_i is true, else flag_i is false)

  // Constraint: Pop element if flag is true
  enforce(if flag_i is true, then (current_b_i, B_i+1) = pop(B_i))

  // Constraint: Check validity if flag is true
  enforce(if flag_i is true, then is_valid(current_b_i) is true)
}

// No explicit output; satisfaction of constraints IS the result.
output: None
```

These intermediate variables (`flag_i`, `current_b_i`, etc.) are crucial parts of the **witness** the prover must generate. They don't exist in the original Python code but are necessary to link the steps together arithmetically for the proof system.

We'd need a similar `CheckerV` circuit.

**Step 3: The Main Validation Circuit (Composition)**

Combine the circuits. `fit(circuit, input, output)` means the inputs/outputs satisfy that circuit's constraints. This composition is fundamental in complex ZK systems like zkEVMs, where proofs for individual opcodes or steps are combined to prove a whole transaction or block.

```plaintext
// Circuit: MainValidator
input: data_structure h // Public input

// Intermediate witness: B[], V[] from Decomposer
intermediate: elements_B B[], elements_V V[]

// Constraint 1: Decompose h correctly using Decomposer circuit
enforce(fit(Decomposer, h, (B[], V[])))

// Constraint 2: Check B elements if needed, using CheckerB circuit
enforce(if B[] is nonempty, then fit(CheckerB, B[], ()))

// Constraint 3: Check V elements if needed, using CheckerV circuit
enforce(if V[] is nonempty, then fit(CheckerV, V[], ()))

output: None // Validity proven by the existence of the ZK proof itself
```

**Why** `output: None` Still Makes Sense

In ZK proofs, you don't typically get a boolean "*true/false*" output from the circuit logic itself. The ZK proof *is* the output:

* If the prover can generate a valid proof that the verifier accepts, it means all constraints were satisfied for the given public inputs and the (potentially private) witness. The statement is implicitly "*true*".
    
* If no such proof can be generated (because constraints conflict), the statement is implicitly "*false*".
    

**Here's a point to consider:**

Look at `CheckerB` / `CheckerV` and `MainValidator`. Assumption: max 5 elements each. Where's the potential bug in this setup?

> *Pause and think... what if the input data violates the assumptions?*
> 
> …
> 
> *Consider the loop boundary*
> 
> …
> 
> *Have an idea?*

**The potential vulnerability here is related to assumptions.** The bug hinges on that "*max 5 elements*" assumption. What if the *actual* input `h` can yield *6* 'B' elements, and the 6th one is invalid (`is_valid(b6)` is false)?

Our `CheckerB` only loops 5 times. It checks `b0` through `b4` and stops. The 6th invalid element `b6` is never examined. A prover could still potentially satisfy all constraints for the first 5 steps and generate a proof, effectively vouching for an invalid `h`.

This is a **soundness bug**. An invalid state/input can lead to an accepted proof. In a zkEVM context, this would be catastrophic – allowing invalid transactions or state changes to be finalized on L1.

**The "Fix" and its Trade-off**

What if we add `enforce(B5 is empty)` to `CheckerB`? Now, the 6-element invalid input fails the check. Good.

But... what if a *valid* `h` genuinely has 6 *valid* 'B' elements? Now, our modified circuit *cannot* prove this valid input, because `B5` won't be empty.

This is a **completeness bug**. A valid state/input cannot be proven. For a zkEVM, this means valid transactions could be unfairly rejected or censored. Balancing soundness and completeness under all input conditions is critical.

---

## A ZK Processing Pipeline

Let's model a simple processing pipeline, analogous to proving sequential operations in a zkEVM (like executing [EVM](https://ethereum.org/en/developers/docs/evm/) opcodes one after another). Max limit 5 again.

**Inputs:** `raw_B[]`, `raw_V[]`

**Circuits:**

1. `ProcessorB`: Processes `raw_B[]` -&gt; `cooked_B[]`. (Think: Prove execution of some function/opcode)
    
2. `ProcessorV`: Processes `raw_V[]` -&gt; `cooked_V[]`.
    
3. `Assembler`: Combines `cooked_B[]`, `cooked_V[]` -&gt; `output_H`. (Think: Prove final state assembly)
    

```plaintext
// Circuit: ProcessorB
input: raw_elements_B rB[]
// ... (loop 5 times, process rb_i -> cb_i, push to cB) ...
// Constraints define the state transition for each step
enforce(if flag_i is true, then cb_i = process_element_B(rb_i)) // The core logic
enforce(if flag_i is true, then cB_i+1 = cB_i.push(cb_i)) // State update
// ... other constraints for flags, popping, empty checks ...
output: cooked_elements_B cB[]
```

```plaintext
// Circuit: ProcessorV (Similar)
input: raw_elements_V rV[]
output: cooked_elements_V cV[]
```

```plaintext
// Circuit: Assembler
input: cooked_elements_B cB[], cooked_elements_V cV[]
enforce(output_H is assembled_from(cB[], cV[])) // Final check
output: final_structure output_H
```

**The Main Pipeline Circuit (Composition)**

This circuit proves the correct sequence and data flow between the processing steps.

```plaintext
// Circuit: MainPipeline
input: raw_elements_B rB[], raw_elements_V rV[] // Initial state/input

// Intermediate witness: cB[], cV[] (Results of processing steps)
intermediate: cooked_elements_B cB[], cooked_elements_V cV[]

// Constraint: Prove ProcessorB execution if needed
// Recall: fit(Circuit, inputs, outputs) checks constraint satisfaction
enforce(if rB[] is nonempty, then fit(ProcessorB, rB[], cB[]))
// Add constraint: if rB[] is empty, enforce cB[] is empty too?

// Constraint: Prove ProcessorV execution if needed
enforce(if rV[] is nonempty, then fit(ProcessorV, rV[], cV[]))
// Add constraint: if rV[] is empty, enforce cV[] is empty too?

// Constraint: Prove Assembler execution using intermediate results
enforce(fit(Assembler, (cB[], cV[]), output_H))

output: final_structure output_H // Final proven state/output
```

**Now, let's examine the pipeline:**

Focus on this processing structure. Assume `process_element_B`, `process_element_V`, `assembled_from` are correct *in isolation*.

> *Where might a bug lie in the composition or state handling between these provable steps?*
> 
> It's not the length bug again. Think about what the prover supplies and what constraints ensure the integrity *across* the steps. This kind of inter-circuit consistency is a major challenge when building complex systems like any of the various [Ethereum Layer 2 networks](https://decrypt.co/resources/what-is-zkevm?amp=1).
> 
> *(Hint: What guarantees that the* `cB[]` used by the `Assembler` is *actually* the one produced by `ProcessorB`?)
> 
> *The potential issue here is subtle and relates to the composition of these circuits. Think about the guarantees (or lack thereof) regarding data passed between them.*

---

**<mark>Can you spot the bug?</mark>**

*(Since this is an open scenario, you might find some answers that seem reasonable. However, if you're not 100% confident in your answer, it's likely you haven't found the one I hope you to find.)*

That's the brain dump for now! Building robust ZK circuits, especially for something as complex as a zkEVM, requires meticulous handling of constraints, witness data, assumptions, and the composition of proofs. It's where cryptography, logic, and software engineering meet security.

### [**zkevm.dev**](https://zkevm.dev)