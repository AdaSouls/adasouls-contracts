//// Scenario tests. Keys and signatures were produced offline with Ed25519
//// over the exact bytes of `alma/vote.message` (see spike/gen-vote-vectors.py
//// in this repo); the human key here is the test key with seed 0x11..11.

use agent_drep.{Advance, Agent, Create, Destroy, Human, Rotate, State}
use aiken/crypto.{blake2b_224}
use aiken/interval
use alma/vote.{Authorization}
use cardano/address.{Script}
use cardano/assets
use cardano/certificate.{
  RegisterDelegateRepresentative, UpdateDelegateRepresentative,
}
use cardano/governance.{DelegateRepresentative, GovernanceActionId, No, Yes}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}

// ---------- fixtures ----------

const drep = #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const human_vkey =
  #"d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"

const agent_vkh = #"0101010101010101010101010101010101010101010101010101010101"

const gov_tx =
  #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

const sig_yes_seq0 =
  #"a4f81460f86c6852a7bec75466368682f0cfdfca5c3722258a1e57c2ed0ff67ec96b00aac0f0d0e42e2a602e54e28190150bb5bb6bb297607fcfd300e1a02701"

const sig_yes_seq1 =
  #"77ba18c498f53908a8b4c866a5c78ce22bcb7a13b6dbe6bfd2a977d4b79c91b5b42976ba24c75e5f6caf157084b2b14d24183f7fa4f6a3e71fe4f2427b45390a"

const sig_no_seq0 =
  #"0692693152bc5c14173b13334036bd9e4830c0c65474b3987efcdbff1e0096588d15a44efafdea73fb41916c6c6988882a61ebb779b82a231be8af9c2b224b08"

const sig_by_other_yes_seq0 =
  #"4c2a38378eabd95292c66a59e673694fabc4b79dca5ab8833389cab457b7a34963d8200ff0d2e63c9aab6060ca6e3607f1aa28afee78d6e5e8f6a096b0320f01"

const seed =
  OutputReference {
    transaction_id: #"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    output_index: 0,
  }

const state_ref =
  OutputReference {
    transaction_id: #"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    output_index: 0,
  }

const action = GovernanceActionId { transaction: gov_tx, proposal_procedure: 0 }

const voter = DelegateRepresentative(Script(drep))

fn human_vkh() {
  blake2b_224(human_vkey)
}

fn state(sequence: Int) -> State {
  State { sequence, human_vkey, agent_vkh }
}

fn state_output(s: State, token_policy: ByteArray) -> Output {
  Output {
    address: address.from_script(drep),
    value: assets.from_lovelace(2_000_000)
      |> assets.add(token_policy, agent_drep.state_token_name, 1),
    datum: InlineDatum(s),
    reference_script: None,
  }
}

fn state_input(s: State) -> Input {
  Input { output_reference: state_ref, output: state_output(s, drep) }
}

fn authorization(vote, sequence, expires_at) -> Authorization {
  Authorization { action, vote, sequence, expires_at }
}

/// A well-formed agent vote: state spent and advanced, agent witness,
/// validity range ending before the deadline, exactly one vote.
fn agent_vote_tx(sequence: Int, vote, deadline: Int) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [state_input(state(sequence))],
    outputs: [state_output(state(sequence + 1), drep)],
    extra_signatories: [agent_vkh],
    validity_range: interval.between(0, deadline),
    votes: [Pair(voter, [Pair(action, vote)])],
  }
}

// ---------- agent votes ----------

test agent_casts_the_authorized_vote() {
  let tx = agent_vote_tx(0, Yes, 900)
  agent_drep.agent_drep.vote(
    seed,
    Agent {
      authorization: authorization(Yes, 0, 1000),
      signature: sig_yes_seq0,
    },
    voter,
    tx,
  ) && agent_drep.agent_drep.spend(seed, Some(state(0)), Advance, state_ref, tx)
}

test agent_vote_fails_after_expiry() fail {
  let tx = agent_vote_tx(0, Yes, 1001)
  agent_drep.agent_drep.vote(
    seed,
    Agent {
      authorization: authorization(Yes, 0, 1000),
      signature: sig_yes_seq0,
    },
    voter,
    tx,
  )
}

test agent_vote_fails_with_open_ended_validity() fail {
  let tx = Transaction {
    ..agent_vote_tx(0, Yes, 900),
    validity_range: interval.after(0),
  }
  agent_drep.agent_drep.vote(
    seed,
    Agent {
      authorization: authorization(Yes, 0, 1000),
      signature: sig_yes_seq0,
    },
    voter,
    tx,
  )
}

test agent_cannot_change_the_vote() fail {
  // Authorized Yes, transaction votes No.
  let tx = agent_vote_tx(0, No, 900)
  agent_drep.agent_drep.vote(
    seed,
    Agent {
      authorization: authorization(Yes, 0, 1000),
      signature: sig_yes_seq0,
    },
    voter,
    tx,
  )
}

test agent_cannot_add_a_second_vote() fail {
  let other_action = GovernanceActionId { ..action, proposal_procedure: 1 }
  let tx = Transaction {
    ..agent_vote_tx(0, Yes, 900),
    votes: [Pair(voter, [Pair(action, Yes), Pair(other_action, Yes)])],
  }
  agent_drep.agent_drep.vote(
    seed,
    Agent {
      authorization: authorization(Yes, 0, 1000),
      signature: sig_yes_seq0,
    },
    voter,
    tx,
  )
}

test replayed_authorization_fails_once_sequence_moved() fail {
  // Signed for sequence 0; the state is already at 1.
  let tx = agent_vote_tx(1, Yes, 900)
  agent_drep.agent_drep.vote(
    seed,
    Agent {
      authorization: authorization(Yes, 0, 1000),
      signature: sig_yes_seq0,
    },
    voter,
    tx,
  )
}

test authorization_for_a_later_sequence_is_not_valid_yet() fail {
  let tx = agent_vote_tx(0, Yes, 900)
  agent_drep.agent_drep.vote(
    seed,
    Agent {
      authorization: authorization(Yes, 1, 1000),
      signature: sig_yes_seq1,
    },
    voter,
    tx,
  )
}

test signature_by_someone_else_fails() fail {
  let tx = agent_vote_tx(0, Yes, 900)
  agent_drep.agent_drep.vote(
    seed,
    Agent {
      authorization: authorization(Yes, 0, 1000),
      signature: sig_by_other_yes_seq0,
    },
    voter,
    tx,
  )
}

test signature_over_a_different_vote_fails() fail {
  // sig_no_seq0 signs "No"; the redeemer claims Yes.
  let tx = agent_vote_tx(0, Yes, 900)
  agent_drep.agent_drep.vote(
    seed,
    Agent { authorization: authorization(Yes, 0, 1000), signature: sig_no_seq0 },
    voter,
    tx,
  )
}

test agent_vote_fails_without_agent_witness() fail {
  let tx = Transaction { ..agent_vote_tx(0, Yes, 900), extra_signatories: [] }
  agent_drep.agent_drep.vote(
    seed,
    Agent {
      authorization: authorization(Yes, 0, 1000),
      signature: sig_yes_seq0,
    },
    voter,
    tx,
  )
}

test fake_state_token_is_ignored() fail {
  // Same datum, but the token is under another policy: not our state.
  let fake_policy = #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  let tx = Transaction {
    ..agent_vote_tx(0, Yes, 900),
    inputs: [
      Input {
        output_reference: state_ref,
        output: state_output(state(0), fake_policy),
      },
    ],
  }
  agent_drep.agent_drep.vote(
    seed,
    Agent {
      authorization: authorization(Yes, 0, 1000),
      signature: sig_yes_seq0,
    },
    voter,
    tx,
  )
}

// ---------- the state UTxO ----------

test advance_must_increment_by_exactly_one() fail {
  let tx = Transaction {
    ..agent_vote_tx(0, Yes, 900),
    outputs: [state_output(state(2), drep)],
  }
  agent_drep.agent_drep.spend(seed, Some(state(0)), Advance, state_ref, tx)
}

test advance_cannot_change_keys() fail {
  let tampered = State { ..state(1), agent_vkh: #"02" }
  let tx = Transaction {
    ..agent_vote_tx(0, Yes, 900),
    outputs: [state_output(tampered, drep)],
  }
  agent_drep.agent_drep.spend(seed, Some(state(0)), Advance, state_ref, tx)
}

test advance_without_a_vote_fails() fail {
  // The agent cannot burn sequences to void the human's authorizations.
  let tx = Transaction { ..agent_vote_tx(0, Yes, 900), votes: [] }
  agent_drep.agent_drep.spend(seed, Some(state(0)), Advance, state_ref, tx)
}

test human_rotates_the_agent_key() {
  let rotated = State { ..state(0), agent_vkh: #"02" }
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [state_input(state(0))],
    outputs: [state_output(rotated, drep)],
    extra_signatories: [human_vkh()],
  }
  agent_drep.agent_drep.spend(seed, Some(state(0)), Rotate, state_ref, tx)
}

test human_voids_outstanding_authorizations_by_jumping_sequence() {
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [state_input(state(3))],
    outputs: [state_output(state(100), drep)],
    extra_signatories: [human_vkh()],
  }
  agent_drep.agent_drep.spend(seed, Some(state(3)), Rotate, state_ref, tx)
}

test rotate_without_the_human_fails() fail {
  let rotated = State { ..state(0), agent_vkh: #"02" }
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [state_input(state(0))],
    outputs: [state_output(rotated, drep)],
    extra_signatories: [agent_vkh],
  }
  agent_drep.agent_drep.spend(seed, Some(state(0)), Rotate, state_ref, tx)
}

test rotate_cannot_rewind_the_sequence() fail {
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [state_input(state(5))],
    outputs: [state_output(state(4), drep)],
    extra_signatories: [human_vkh()],
  }
  agent_drep.agent_drep.spend(seed, Some(state(5)), Rotate, state_ref, tx)
}

// ---------- the human ----------

test human_votes_directly_with_state_as_reference() {
  let tx = Transaction {
    ..transaction.placeholder,
    reference_inputs: [state_input(state(7))],
    extra_signatories: [human_vkh()],
    votes: [Pair(voter, [Pair(action, No)])],
  }
  agent_drep.agent_drep.vote(seed, Human, voter, tx)
}

test agent_cannot_use_the_human_path() fail {
  let tx = Transaction {
    ..transaction.placeholder,
    reference_inputs: [state_input(state(7))],
    extra_signatories: [agent_vkh],
    votes: [Pair(voter, [Pair(action, No)])],
  }
  agent_drep.agent_drep.vote(seed, Human, voter, tx)
}

test human_registers_the_drep() {
  let cert = RegisterDelegateRepresentative {
    delegate_representative: Script(drep),
    deposit: 500_000_000,
  }
  let tx = Transaction {
    ..transaction.placeholder,
    reference_inputs: [state_input(state(0))],
    extra_signatories: [human_vkh()],
    certificates: [cert],
  }
  agent_drep.agent_drep.publish(seed, Void, cert, tx)
}

test agent_cannot_update_the_drep() fail {
  let cert = UpdateDelegateRepresentative {
    delegate_representative: Script(drep),
  }
  let tx = Transaction {
    ..transaction.placeholder,
    reference_inputs: [state_input(state(0))],
    extra_signatories: [agent_vkh],
    certificates: [cert],
  }
  agent_drep.agent_drep.publish(seed, Void, cert, tx)
}

// ---------- minting the state token ----------

test human_creates_the_state_once() {
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [
      Input {
        output_reference: seed,
        output: Output {
          address: address.from_verification_key(human_vkh()),
          value: assets.from_lovelace(10_000_000),
          datum: NoDatum,
          reference_script: None,
        },
      },
    ],
    outputs: [state_output(state(0), drep)],
    mint: assets.from_asset(drep, agent_drep.state_token_name, 1),
    extra_signatories: [human_vkh()],
  }
  agent_drep.agent_drep.mint(seed, Create, drep, tx)
}

test create_without_the_seed_fails() fail {
  let tx = Transaction {
    ..transaction.placeholder,
    outputs: [state_output(state(0), drep)],
    mint: assets.from_asset(drep, agent_drep.state_token_name, 1),
    extra_signatories: [human_vkh()],
  }
  agent_drep.agent_drep.mint(seed, Create, drep, tx)
}

test human_destroys_the_state() {
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [state_input(state(9))],
    mint: assets.from_asset(drep, agent_drep.state_token_name, -1),
    extra_signatories: [human_vkh()],
  }
  agent_drep.agent_drep.mint(seed, Destroy, drep, tx) && agent_drep.agent_drep.spend(
    seed,
    Some(state(9)),
    Rotate,
    state_ref,
    tx,
  )
}
