"""
ladder_block_store.py
-----------------------
A fake inventory of program blocks (OB1, FC1, DB1, DB2...) that an
attacker can enumerate and read via S7's upload mechanism, and that gets
genuinely overwritten if they push a download -- letting the honeypot
capture exactly what content someone tries to plant, and later serve it
back if they (or someone else) reads it again.

HONESTY NOTE ON BLOCK CONTENT: this does NOT contain real, decompilable
MC7 ladder-logic bytecode. Siemens' MC7 instruction encoding isn't
something I have a verified, complete public specification for to
reconstruct faithfully. What's here is a structurally plausible block
header (matching the general shape real S7 blocks have: block type,
number, length, load-memory size, a timestamp-like field) followed by
filler bytes sized realistically for the block type. It will look like
"a block" to size/inventory-level inspection (block list, block size,
block count) but will NOT decompile into working ladder logic in a real
engineering tool, and a sophisticated attacker who actually tries to
disassemble it will notice. Treat this as covering the "does this device
have a program, and will it let me read/write blocks" question, not as
a faithful ladder-logic honeypot.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


# S7 block type identifiers as used in block-name/upload references
BLOCK_TYPE_OB = 0x38  # Organization Block
BLOCK_TYPE_DB = 0x41  # Data Block
BLOCK_TYPE_FC = 0x43  # Function
BLOCK_TYPE_FB = 0x45  # Function Block

BLOCK_TYPE_NAMES = {
    BLOCK_TYPE_OB: "OB",
    BLOCK_TYPE_DB: "DB",
    BLOCK_TYPE_FC: "FC",
    BLOCK_TYPE_FB: "FB",
}


def _fake_block_content(block_type: int, number: int, size: int) -> bytes:
    """Build a structurally-plausible-but-not-real block payload. See
    module docstring's honesty note -- this is filler with a real-shaped
    header, not working MC7 bytecode."""
    header = bytes([
        block_type,
        (number >> 8) & 0xFF, number & 0xFF,
        (size >> 8) & 0xFF, size & 0xFF,
    ])
    # Deterministic filler (not random) so repeated reads return
    # identical bytes, which matters for looking consistent under
    # repeated polling -- real block content doesn't change between
    # reads unless someone rewrites it.
    filler = bytes(((i * 31 + number) % 256) for i in range(max(size - len(header), 0)))
    return header + filler


@dataclass
class Block:
    block_type: int
    number: int
    content: bytes
    last_modified: float = field(default_factory=time.time)

    @property
    def name(self) -> str:
        return f"{BLOCK_TYPE_NAMES.get(self.block_type, '??')}{self.number}"

    @property
    def size(self) -> int:
        return len(self.content)


class BlockStore:
    """
    Thread-safe in-memory block inventory. Seeded with a small default
    program (OB1 as the main cyclic block calling FC1, plus DB1/DB2 --
    DB1 deliberately matches the DB number process_simulator.py writes
    process values into, so the block inventory and the "live data" DB
    are at least numbered consistently with each other).
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._blocks: dict[tuple[int, int], Block] = {}
        self._seed_default_program()

    def _seed_default_program(self) -> None:
        defaults = [
            (BLOCK_TYPE_OB, 1, 128),   # OB1 -- main cyclic execution block
            (BLOCK_TYPE_FC, 1, 256),
            (BLOCK_TYPE_DB, 1, 64),    # matches process_simulator's DB1
            (BLOCK_TYPE_DB, 2, 32),
        ]
        for block_type, number, size in defaults:
            content = _fake_block_content(block_type, number, size)
            self._blocks[(block_type, number)] = Block(block_type, number, content)

    def list_blocks(self) -> list[Block]:
        with self._lock:
            return list(self._blocks.values())

    def get_block(self, block_type: int, number: int) -> Block | None:
        with self._lock:
            return self._blocks.get((block_type, number))

    def write_block(self, block_type: int, number: int, content: bytes) -> None:
        """Called when an attacker's Download Block payload is committed
        (Download Ended received). This genuinely replaces the fake
        block content with whatever they sent -- so a subsequent Upload
        of the same block will serve back exactly what they planted,
        which is realistic (a real vulnerable device does the same) and
        useful for confirming what payload they were actually testing
        for persistence/effect."""
        with self._lock:
            self._blocks[(block_type, number)] = Block(block_type, number, content)
