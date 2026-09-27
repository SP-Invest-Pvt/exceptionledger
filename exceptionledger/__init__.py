"""exceptionledger: a tamper-evident ledger for security policy exceptions."""

__version__ = "0.1.0"


class LedgerError(Exception):
    """A usage or input problem (unknown id, bad file). The CLI exits 2."""


class TransitionError(Exception):
    """A lifecycle rule was broken (illegal transition, self-approval). The CLI exits 1."""
