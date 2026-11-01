"""Bitcoin Script opcode execution."""

from .interpreter import (
    ScriptError,
    ScriptFlags,
    ScriptTransactionContext,
    eval_script,
    eval_tapscript,
    verify_script,
)
from .sighash import (
    TransactionSignatureChecker,
    legacy_signature_hash,
    witness_v0_signature_hash,
)
from .taproot import (
    SpentOutput,
    TaprootSignatureChecker,
    tapleaf_hash,
    taproot_signature_hash,
    verify_taproot_commitment,
    verify_taproot_keypath,
    verify_taproot_scriptpath,
)
from .witness import get_witness_program, verify_segwit_input, verify_witness_v0
from .validation import verify_transaction_input

__all__ = [
    "ScriptError",
    "ScriptFlags",
    "ScriptTransactionContext",
    "SpentOutput",
    "TaprootSignatureChecker",
    "TransactionSignatureChecker",
    "eval_script",
    "eval_tapscript",
    "get_witness_program",
    "legacy_signature_hash",
    "tapleaf_hash",
    "taproot_signature_hash",
    "verify_script",
    "verify_transaction_input",
    "verify_segwit_input",
    "verify_taproot_commitment",
    "verify_taproot_keypath",
    "verify_taproot_scriptpath",
    "verify_witness_v0",
    "witness_v0_signature_hash",
]
