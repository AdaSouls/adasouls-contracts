//// A DRep with a mandate.
////
//// The script is the DRep credential. A human owns it; an agent may cast
//// exactly the votes the human signed, once each, before they expire. The
//// human can always vote directly, register or update the DRep, and
//// rotate either key without changing the script hash, so the DRep keeps
//// its delegations.
////
//// State lives in one UTxO at the script address, marked by a token this
//// same script mints once (its policy id is the script hash):
////
////   State { sequence, human_vkey, agent_vkh }
////
//// - `sequence` is the replay guard: an authorization names the sequence it
////   is good for, and the agent's vote must spend the state UTxO and write
////   it back with `sequence + 1`. A signed authorization the human regrets
////   dies the moment the sequence moves on.
//// - `human_vkey` is the raw Ed25519 key that signs authorizations, and
////   whose hash must witness anything the human does directly.
//// - `agent_vkh` is the key that must witness the agent's transactions.
////
//// Nothing here holds or moves funds. The script never sees a private key:
//// the human's signature arrives inside the redeemer, the agent's as an
//// ordinary transaction witness.

use aiken/collection/dict
use aiken/collection/list
use aiken/collection/pairs
use aiken/crypto.{
  Signature, VerificationKey, VerificationKeyHash, blake2b_224,
  verify_ed25519_signature,
}
use aiken/interval.{Finite}
use alma/vote.{Authorization} as mandate
use cardano/address.{Script}
use cardano/assets.{PolicyId}
use cardano/certificate.{Certificate}
use cardano/governance.{DelegateRepresentative, Voter}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction,
}

pub const state_token_name: ByteArray = "alma-drep-state"

pub type State {
  sequence: Int,
  human_vkey: VerificationKey,
  agent_vkh: VerificationKeyHash,
}

pub type VoteRedeemer {
  /// The human votes directly. The state UTxO is a reference input.
  Human
  /// The agent casts a vote the human signed. The state UTxO is spent.
  Agent { authorization: Authorization, signature: Signature }
}

pub type StateRedeemer {
  /// The agent advances `sequence` by one, in the same transaction as its vote.
  Advance
  /// The human rewrites the state: new keys, or a sequence jump to void outstanding authorizations.
  Rotate
}

pub type MintRedeemer {
  Create
  Destroy
}

validator agent_drep(seed: OutputReference) {
  /// The state token is minted once, when the seed UTxO is spent, into the
  /// script address with a State the human signs for. It can be burned by
  /// the human to retire the DRep.
  mint(redeemer: MintRedeemer, policy_id: PolicyId, self: Transaction) {
    when redeemer is {
      Create -> {
        expect [Pair(name, 1)] = self.mint
          |> assets.tokens(policy_id)
          |> dict.to_pairs
        expect name == state_token_name
        expect list.any(self.inputs, fn(i) { i.output_reference == seed })
        expect Some(state) = continuing_state(self.outputs, policy_id)
        human_signed(self, state)
      }
      Destroy -> {
        expect [Pair(name, -1)] = self.mint
          |> assets.tokens(policy_id)
          |> dict.to_pairs
        expect name == state_token_name
        expect Some(state) = spent_state(self.inputs, policy_id)
        human_signed(self, state)
      }
    }
  }

  /// Spending the state UTxO.
  spend(
    datum: Option<State>,
    redeemer: StateRedeemer,
    utxo: OutputReference,
    self: Transaction,
  ) {
    expect Some(state) = datum
    expect Some(own_input) = transaction.find_input(self.inputs, utxo)
    expect Script(own_hash) = own_input.output.address.payment_credential
    when redeemer is {
      Advance -> {
        // Only alongside a vote by this DRep: the agent cannot burn
        // sequences on its own to void what the human signed.
        expect
          pairs.has_key(self.votes, DelegateRepresentative(Script(own_hash)))
        expect list.has(self.extra_signatories, state.agent_vkh)
        expect Some(next) = continuing_state(self.outputs, own_hash)
        next == State { ..state, sequence: state.sequence + 1 }
      }
      Rotate -> {
        expect human_signed(self, state)
        when continuing_state(self.outputs, own_hash) is {
          Some(next) -> next.sequence >= state.sequence
          // No continuing state: only valid if the token is being burned,
          // which the mint handler checks with the human's signature.
          None ->
            assets.quantity_of(self.mint, own_hash, state_token_name) == -1
        }
      }
    }
  }

  /// Casting a vote as this DRep.
  vote(redeemer: VoteRedeemer, voter: Voter, self: Transaction) {
    expect DelegateRepresentative(Script(own_hash)) = voter
    when redeemer is {
      Human -> {
        expect Some(state) = referenced_state(self, own_hash)
        human_signed(self, state)
      }
      Agent { authorization, signature } -> {
        // The state must be spent (and advanced, which the spend handler checks).
        expect Some(state) = spent_state(self.inputs, own_hash)
        expect list.has(self.extra_signatories, state.agent_vkh)
        expect authorization.sequence == state.sequence
        expect
          verify_ed25519_signature(
            state.human_vkey,
            mandate.message(own_hash, authorization),
            signature,
          )
        expect not_after(self, authorization.expires_at)
        // Exactly the authorized vote, and nothing else, from this voter.
        expect Some(procedures) = pairs.get_first(self.votes, voter)
        procedures == [Pair(authorization.action, authorization.vote)]
      }
    }
  }

  /// DRep registration, updates and deregistration: the human only.
  publish(_redeemer: Data, certificate: Certificate, self: Transaction) {
    expect Some(own_hash) = drep_of(certificate)
    expect Some(state) = referenced_state(self, own_hash)
    human_signed(self, state)
  }

  else(_) {
    fail
  }
}

// ---------- helpers ----------

fn human_signed(self: Transaction, state: State) -> Bool {
  list.has(self.extra_signatories, blake2b_224(state.human_vkey))
}

/// The validity range ends at a known time no later than `deadline`.
fn not_after(self: Transaction, deadline: Int) -> Bool {
  when self.validity_range.upper_bound.bound_type is {
    Finite(t) -> t <= deadline
    _ -> False
  }
}

fn carries_state_token(output: Output, own_hash: PolicyId) -> Bool {
  assets.quantity_of(output.value, own_hash, state_token_name) == 1
}

fn state_of(output: Output, own_hash: PolicyId) -> Option<State> {
  if output.address.payment_credential == Script(own_hash) && carries_state_token(
    output,
    own_hash,
  ) {
    expect InlineDatum(data) = output.datum
    expect state: State = data
    Some(state)
  } else {
    None
  }
}

fn first_state(outputs: List<Output>, own_hash: PolicyId) -> Option<State> {
  when outputs is {
    [] -> None
    [output, ..rest] ->
      when state_of(output, own_hash) is {
        Some(state) -> Some(state)
        None -> first_state(rest, own_hash)
      }
  }
}

fn continuing_state(outputs: List<Output>, own_hash: PolicyId) -> Option<State> {
  first_state(outputs, own_hash)
}

fn spent_state(inputs: List<Input>, own_hash: PolicyId) -> Option<State> {
  first_state(list.map(inputs, fn(i) { i.output }), own_hash)
}

/// The state, spent or referenced: whichever the transaction carries.
fn referenced_state(self: Transaction, own_hash: PolicyId) -> Option<State> {
  when spent_state(self.reference_inputs, own_hash) is {
    Some(state) -> Some(state)
    None -> spent_state(self.inputs, own_hash)
  }
}

fn drep_of(certificate: Certificate) -> Option<PolicyId> {
  when certificate is {
    certificate.RegisterDelegateRepresentative {
      delegate_representative: Script(hash),
      ..
    } -> Some(hash)
    certificate.UpdateDelegateRepresentative{delegate_representative: Script(
      hash,
    )} -> Some(hash)
    certificate.UnregisterDelegateRepresentative {
      delegate_representative: Script(hash),
      ..
    } -> Some(hash)
    _ -> None
  }
}
