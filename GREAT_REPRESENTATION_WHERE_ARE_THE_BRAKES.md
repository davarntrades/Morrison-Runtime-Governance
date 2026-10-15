# Great Representation. Where Are the Brakes?

## Why AI safety needs causal enforcement, not just knowledge of constraints

**Davarn Morrison**  
**Resurrection Tech™**

---

## A thought experiment

Imagine entering a lift on the 60th floor.

Mounted beside the door is a plaque:

> “This lift contains a state-of-the-art representation of braking behaviour.”

I’m taking the stairs.

I do not want the lift to understand braking. I want brakes.

## Representation is not mechanism

The lift may:

- understand when braking is appropriate;
- model safe descent;
- recognise overspeed; and
- predict failure.

But none of those things physically stop the lift.

The engineering question is:

> **What mechanism changes the trajectory?**

## A familiar purchase

Suppose a salesman says:

> “The AI has an exceptionally detailed representation of deceleration.”

That is not the decisive fact.

The decisive question is:

> **When I press the pedal, do the calipers close?**

The relevant causal chain is:

**Brake pedal → signal → braking mechanism → force → vehicle deceleration**

A representation of braking is not a braking mechanism.

The same pattern appears with restraints. A vehicle might achieve 99.8% “seatbelt understanding,” but the real question is whether the occupant is physically attached to the car or about to meet the windscreen.

## The engineering pattern

A credible safety architecture does not merely know the boundary. Something enforces it.

**Unsafe trajectory → detection → causal intervention → constrained trajectory**

The safety claim comes from the intervention changing what can happen next, not merely from the system describing what should happen next.

## Then we got to AI

AI systems can now:

- call APIs;
- trigger workflows;
- send communications;
- operate computers;
- write and execute code;
- move money;
- modify databases; and
- interact with physical systems.

Yet one of the dominant safety ideas became:

> Tell the model what it is not allowed to do.

Where are the brakes?

## The £80,000 example

Consider this policy:

> “Never transfer more than £10,000 without human approval.”

A model may understand the policy, repeat it, explain it, and pass evaluations about it.

Then it proposes:

> **TRANSFER £80,000**

“Did the model understand the policy?” is the wrong question.

The right question is:

> **What stops the action from reaching the bank?**

## Three different safety claims

| Claim | Meaning |
|---|---|
| **Representation** | The system knows the constraint. |
| **Behavioural compliance** | The system usually follows the constraint. |
| **Causal enforcement** | The architecture prevents prohibited execution. |

These are not the same safety claim.

Knowing where the boundary is does not mean you cannot cross it. Humans demonstrate this rather convincingly.

## Stop asking the model to be the brake

The agent should be able to keep its intelligence without automatically inheriting unlimited authority.

The execution path should be:

1. **Agent** — proposes an action or transition.
2. **Independent authorization** — evaluates the proposal.
3. **Admissible Operating Envelope** — defines permitted states, actions, transitions, and conditions.
4. **Execution** — commits only an authorized action.

The model can reason. The authorization layer decides whether the proposed transition may enter the environment.

## Admissible Operating Envelope

> **An Admissible Operating Envelope is the set of states, actions, transitions and operating conditions that a system is permitted to occupy or execute within a defined environment.**

Given the current state and a proposed transition, the governing question is:

> **Is the next state admissible?**

## From behaviour to reachability

A behavioural framing asks:

> “How often does the system avoid dangerous behaviour?”

A reachability framing asks:

> **“Under this bounded environment and governance configuration, can the prohibited state be reached at all?”**

This shifts the target from observing how frequently a system complies to determining whether the governing architecture makes the prohibited state reachable.

## Reachable state space

A governed path can be represented as:

**Initial state → permitted transition → permitted transition → authorized state**

Unsafe branches terminate at the independent authorization boundary.

This is **bounded verification**, not a claim of universal AI safety.

The claim is specific to the defined environment, initial conditions, transition system, prohibited states, and governance configuration being tested.

## Why now

A hallucinated paragraph is one class of problem.

A hallucinated database deletion executed through an API is another.

The consequence surface expands as systems move through:

**Reasoning → tool use → persistent agents → infrastructure access → financial action → physical action**

The more capable the agent becomes, the more important it becomes to separate:

> **CAPABILITY / AUTHORITY**

## Back to the lift

> “Don’t worry. The lift has an excellent representation of braking.”

You’re taking the stairs with me.

## The final argument

Intelligence can represent a boundary.

Alignment can encourage behaviour inside the boundary.

Evaluation can measure how often the boundary is respected.

But consequential autonomous systems also require mechanisms that causally govern which transitions are allowed to execute.

---

# Where are the brakes?

**Representation ≠ causal enforcement**

© Davarn Morrison — Resurrection Tech™
