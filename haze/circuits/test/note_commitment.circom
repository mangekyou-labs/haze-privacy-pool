pragma circom 2.2.2;

include "../src/gadgets/note.circom";

component main {public [domain, poolDomain, applicationIdHi, applicationIdLo, value, ownerNotePublicKey, ownerEncryptionKeyHash, blinding]} = NoteCommitment();
