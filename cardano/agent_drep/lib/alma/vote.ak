//// The authorization a human signs so that an agent may cast exactly one
//// vote, once, before a deadline, as the script DRep.
////
//// The signed bytes are a fixed-width concatenation, so any off-chain
//// implementation (TypeScript, Python, a hardware-wallet flow) reproduces
//// them without a CBOR library:
////
////   "alma-drep-vote/1"            16 bytes, the type tag
////   drep script hash              28 bytes: binds the authorization to one DRep
////   governance action tx id       32 bytes
////   proposal procedure index       2 bytes, big-endian
////   vote                           1 byte: No = 0, Yes = 1, Abstain = 2
////   sequence                       8 bytes, big-endian: the state UTxO's counter
////   expires_at                     8 bytes, big-endian: POSIX milliseconds
////
//// 95 bytes in total. The human signs them with Ed25519 (RFC 8032, pure),
//// the same scheme as any Cardano key, so a Ledger-compatible flow or a
//// key file both work. The agent cannot change a single byte without
//// invalidating the signature, and cannot reuse it: the sequence is spent.

use aiken/crypto.{ScriptHash}
use aiken/primitive/bytearray
use cardano/governance.{GovernanceActionId, Vote}

pub const domain: ByteArray = "alma-drep-vote/1"

pub type Authorization {
  action: GovernanceActionId,
  vote: Vote,
  /// Must equal the state UTxO's `sequence` at the time of voting.
  sequence: Int,
  /// POSIX milliseconds. The voting transaction's validity range must end at or before it.
  expires_at: Int,
}

pub fn vote_code(vote: Vote) -> Int {
  when vote is {
    governance.No -> 0
    governance.Yes -> 1
    governance.Abstain -> 2
  }
}

/// The exact bytes the human signs.
pub fn message(drep: ScriptHash, authorization: Authorization) -> ByteArray {
  domain
    |> bytearray.concat(drep)
    |> bytearray.concat(authorization.action.transaction)
    |> bytearray.concat(
        bytearray.from_int_big_endian(
          authorization.action.proposal_procedure,
          2,
        ),
      )
    |> bytearray.concat(
        bytearray.from_int_big_endian(vote_code(authorization.vote), 1),
      )
    |> bytearray.concat(
        bytearray.from_int_big_endian(authorization.sequence, 8),
      )
    |> bytearray.concat(
        bytearray.from_int_big_endian(authorization.expires_at, 8),
      )
}

/// Test vector shared with the off-chain implementation: the same inputs
/// must produce the same 95 bytes there.
test digest_vector() {
  let drep = #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  let authorization = Authorization {
    action: GovernanceActionId {
      transaction: #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      proposal_procedure: 0,
    },
    vote: governance.Yes,
    sequence: 0,
    expires_at: 1000,
  }
  message(drep, authorization) == #"616c6d612d647265702d766f74652f31aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000001000000000000000000000000000003e8"
}

test message_is_95_bytes() {
  let drep = #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  let authorization = Authorization {
    action: GovernanceActionId {
      transaction: #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      proposal_procedure: 65535,
    },
    vote: governance.Abstain,
    sequence: 123456789,
    expires_at: 1_800_000_000_000,
  }
  bytearray.length(message(drep, authorization)) == 95
}
