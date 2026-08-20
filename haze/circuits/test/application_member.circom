pragma circom 2.2.2;

include "../src/gadgets/policy.circom";

component main {public [domain, applicationIdHi, applicationIdLo, notePublicKey, encryptionKeyHash]} = ApplicationMember();
