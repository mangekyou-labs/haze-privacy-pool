pragma circom 2.2.2;

// Frozen keccak(label) mod r constants. Must match haze-protocol-v1.json.
function DOMAIN_PROTOCOL() {
    return 0x2afe8a5679df289719eae23ad89b300434b9dfbb8194dad0b50dee97f91a3868;
}
function DOMAIN_POOL() {
    return 0x2e6bf37683e95a0580a83999cc8f97d94c6971991aedc6c278b6205f22b4e674;
}
function DOMAIN_NOTE_KEY() {
    return 0x020bf885d998812b763118d7ab4e699f02945624138e08b9db4ee8579e975b46;
}
function DOMAIN_ENCRYPTION_KEY() {
    return 0x0eecd4e943e6a980feaf6b2a7b28051bf334f7da7fff0e26fbcee8f616f88afe;
}
function DOMAIN_NOTE() {
    return 0x17a12ec9e6b08630bfca04da26e8acfab8cde9769b87b968bb62adb56066f9a9;
}
function DOMAIN_NULLIFIER() {
    return 0x1c62494a7288d13827418d1fbdcba652ad52b366e6ac484d2917c944507dea3c;
}
function DOMAIN_NOTE_TREE() {
    return 0x29c582b40dae5f68d8dde5f949e8a67df11b1d402cb8ed47125814a77dd97f14;
}
function DOMAIN_APP_TREE() {
    return 0x0e81fbe5bbc6cbfabdddbbd655aa31a23f92755e64aa1b383b89f45ed1789751;
}
function DOMAIN_BLOCK_TREE() {
    return 0x1a07ffad523050eb9557dc596e54e9e9c7f837f32fdfe45f4aba1c3e3f4448f3;
}
function DOMAIN_APP_MEMBER() {
    return 0x160cd10e3eaff43b1426bc69b3fa677c1b158d81ffdbbb88714bda14f99e4dda;
}
function DOMAIN_BLOCK_NOTE() {
    return 0x11eefc4d312d0dc573148fea08df1caf4d8d7415aa9684f51d730472a927a503;
}
function DOMAIN_BLOCK_ADDRESS() {
    return 0x0921cfca0da02e017415735a049888912c67cc0d5d3b72cb9e64a306eff36fb9;
}
function DOMAIN_AUDIT() {
    return 0x1174e1df33753938ddf0b1fbfd3173c8f10392c62a3602074713ebb21c8d2bf5;
}
function BN254_R_MINUS_1() {
    return 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000;
}
