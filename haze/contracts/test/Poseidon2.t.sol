// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {HazePoseidon2} from "../src/HazePoseidon2.sol";

/// @dev Pins the on-chain Poseidon2 parent hash to haze-protocol-v1 merkle vectors.
contract Poseidon2Test is Test {
    uint256 internal constant NOTE_EMPTY_ROOT =
        0x0b70befaf3b699951d686409413a36612ee96094c7bf2708687522123486f908;
    uint256 internal constant BLOCKLIST_SENTINEL_ROOT =
        0x2f9120bf4979f6f079577e2eaeb96fd996129dbd24a0855fbd0fe7e30669716d;
    uint256 internal constant NOTE_PATH_LEAF =
        0x12f9ba3a528b60b24a66982d68570b38eb9a93e96d0224fd1a4cc0051fbbe76f;
    uint256 internal constant NOTE_PATH_ROOT =
        0x108a590eaa62256572787f19fded658153a887e3b5aa6a238762b8f910c980ad;
    uint256 internal constant BLOCKLIST_UPPER =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000;

    function testEmptyNoteRootMatchesFrozenVector() public pure {
        assertEq(
            HazePoseidon2.emptyRoot(HazePoseidon2.domainField(HazePoseidon2.NOTE_TREE)), NOTE_EMPTY_ROOT
        );
    }

    function testBlocklistAdjacentSentinelsRootMatchesFrozenVector() public pure {
        uint256 domain = HazePoseidon2.domainField(HazePoseidon2.BLOCK_TREE);
        uint256[32] memory zeros = HazePoseidon2.zeroHashes(domain);
        uint256 level0 = HazePoseidon2.parentNode(domain, 0, 0, BLOCKLIST_UPPER);
        uint256 node = level0;
        for (uint256 level = 1; level < 32; ++level) {
            node = HazePoseidon2.parentNode(domain, level, node, zeros[level]);
        }
        assertEq(node, BLOCKLIST_SENTINEL_ROOT);
    }

    function testNotePathRootMatchesFrozenVector() public pure {
        uint256 domain = HazePoseidon2.domainField(HazePoseidon2.NOTE_TREE);
        uint256[32] memory siblings = _notePathSiblings();
        uint256 node = NOTE_PATH_LEAF;
        uint256 cursor = 7;
        for (uint256 level = 0; level < 32; ++level) {
            if (cursor & 1 == 0) {
                node = HazePoseidon2.parentNode(domain, level, node, siblings[level]);
            } else {
                node = HazePoseidon2.parentNode(domain, level, siblings[level], node);
            }
            cursor >>= 1;
        }
        assertEq(node, NOTE_PATH_ROOT);
    }

    function _notePathSiblings() internal pure returns (uint256[32] memory siblings) {
        siblings[0] = 0;
        siblings[1] = 0x0a3c59b709aad3e30eefd6b205e397a7be570b5ee0683a075a275d4ae7a55dcf;
        siblings[2] = 0x1a843cff98f1fbf818888d8ab9ae3a911f3b9d09f89d554aa908772ccfc99357;
        siblings[3] = 0x23a9708c24d8db4dec8646d23024c4d1a4caaa1f9c859c033b33b58b38b323bd;
        siblings[4] = 0x2d4b9f7d39d9076246f0bc0f925bd0fbf68769cb416009ceb69c98bd0f621f02;
        siblings[5] = 0x1dd0c168d2a377f6a102ce508881d58914c34c3110c572883f3322ff503b0175;
        siblings[6] = 0x0daa47b94fb2b93dea69e4d25d6548c041cfe8b15d4e5c5a989864571e74fe33;
        siblings[7] = 0x19bc142a4daab94aa50ab8c8474b25439801aa769cbc547812e302f935b04f39;
        siblings[8] = 0x1c8fc3fc5dc0b7bf97effcfdf4f831e51b2929ad49fafafb67859753b108737d;
        siblings[9] = 0x1843d0290e9e9afa1f44fd04d6ea33dade2e90892904e65dbc06912318eeb9cd;
        siblings[10] = 0x1c7df4043e0e34d116bc6a091f914def982adf270c9a5683689e1d6a27beab18;
        siblings[11] = 0x08d5e6933981d43d8510c3a5f83a4ed6a6c5db92b7d82047c39a576ed41d2d59;
        siblings[12] = 0x0ee8f7b3148fc46cc4b4fbd1eb209fd754aebe1fe550dbf991f063a198b6a46b;
        siblings[13] = 0x2364247cc2e5fe56c14f715e729e09bef1142ca27019eb7606af91e33fc9b0f4;
        siblings[14] = 0x166e91dbcc936fb927e7f8bddebab78f8310deb00d175314b8d532cb5edc40a8;
        siblings[15] = 0x0b33d2e19d422d0672e3022a4119672f358ad5f1c983edc79c204451c53027ea;
        siblings[16] = 0x281473ff3dd0e60068375bd23dfbf890dfefae010779e5f235e416dad04ab0da;
        siblings[17] = 0x07d1cd209611a552fd783bb6cbb45f39b70b58457787aa467f53016c1a5ba41d;
        siblings[18] = 0x1c6be1c009a9054383a187785652f645f98e46e661f53abc2247fb848c0718ec;
        siblings[19] = 0x09299df82f2f90e03b38a38c1179fd2cf733057152fa876ed4e1dab140d60d11;
        siblings[20] = 0x01f96f01d80e0f672995bf6509534aee4712b8f6ad51b09c1b1b7dfda86006f8;
        siblings[21] = 0x0379605bf0e955ee69f838d593342a38eca220f30ac0e0e8d7384731fe2ef53a;
        siblings[22] = 0x1a57dbb162153d4da8ecef4b1f7532bf94b8f23b7292aabe77760cb76ab32f88;
        siblings[23] = 0x14d36b96191e1e6895d60942c53523da6f38ebb750b649530431c56d73576d87;
        siblings[24] = 0x0a6b9b25bc436ee26d1e62f546995e57b6469a72515f3752197f7650fcfc0118;
        siblings[25] = 0x1c65fc46cce933b5cc7524d6cf889771a1ebdfa2c788374c7ddd258c7010a91f;
        siblings[26] = 0x11a6cd767c1c6c392d03e07bdd7cc591bccefe1a87842e138d035c2aed2c456e;
        siblings[27] = 0x20dd93d8a633e000cb6046d467f9bf4822de2d3ecc0dc31862bfc3ecaadcfb27;
        siblings[28] = 0x2f421ca86a350004bdc813e9a417b73505048539c7b28de8e36b8c4e8bb56b9b;
        siblings[29] = 0x1f92db245b2e898f7e5a4ce7f9c6c902c80a3012f881f6e2a5530098d453ab97;
        siblings[30] = 0x1ac5f15e5d0c273b06901e1bcb9ee5b9f7278012366fd1e13d2e10208ce5a491;
        siblings[31] = 0x27c86b89524301edc1cd76009a4f7a6156e0a40761bcc227d69fa1d3706a1e3e;
    }
}
