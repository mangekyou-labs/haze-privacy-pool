// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {HazeProtocolVectors} from "../src/HazeProtocolVectors.sol";

contract ProtocolVectorsTest is Test {
    using stdJson for string;

    string internal vectors;

    function setUp() public {
        vectors = vm.readFile(string.concat(vm.projectRoot(), "/../circuits/vectors/v1/haze-protocol-v1.json"));
    }

    function positiveNamed(string memory name) internal view returns (string memory) {
        for (uint256 i = 0; i < 64; ++i) {
            string memory base = string.concat(".positive[", vm.toString(i), "]");
            try this.readPositiveName(base) returns (string memory found) {
                if (keccak256(bytes(found)) == keccak256(bytes(name))) {
                    return base;
                }
            } catch {
                break;
            }
        }
        revert(string.concat("missing positive vector: ", name));
    }

    function readPositiveName(string memory base) external view returns (string memory) {
        return vectors.readString(string.concat(base, ".name"));
    }

    function testSchemaAndTypeHashesMatchCommittedArtifact() public view {
        assertEq(vectors.readUint(".schema_version"), 1);
        string memory types = positiveNamed("eip712_type_hashes");
        assertEq(
            HazeProtocolVectors.domainTypeHash(),
            vectors.readBytes32(string.concat(types, ".domain"))
        );
        assertEq(
            HazeProtocolVectors.intentTypeHash(),
            vectors.readBytes32(string.concat(types, ".intent"))
        );
        assertEq(
            HazeProtocolVectors.authorizationTypeHash(),
            vectors.readBytes32(string.concat(types, ".authorization"))
        );
        assertEq(
            HazeProtocolVectors.keyDerivationTypeHash(),
            vectors.readBytes32(string.concat(types, ".key_derivation"))
        );
    }

    function testProtocolDomainKeccakMatchesCommittedArtifact() public view {
        assertEq(
            HazeProtocolVectors.domainTag("haze/avalanche/v1/protocol"),
            vectors.readBytes32(".domains[0].keccak")
        );
    }

    function testAllThirteenDomainTagsMatchCommittedArtifact() public view {
        for (uint256 i = 0; i < 13; ++i) {
            string memory prefix = string.concat(".domains[", vm.toString(i), "]");
            string memory label = vectors.readString(string.concat(prefix, ".label"));
            assertEq(
                HazeProtocolVectors.domainTag(label),
                vectors.readBytes32(string.concat(prefix, ".keccak"))
            );
        }
    }

    function testFujiDomainSeparatorMatchesCommittedArtifact() public view {
        string memory base = positiveNamed("eip712_domain_separator_fuji");
        bytes32 computed = HazeProtocolVectors.domainSeparator(
            vectors.readString(string.concat(base, ".name_string")),
            vectors.readString(string.concat(base, ".version")),
            vectors.readUint(string.concat(base, ".chain_id")),
            vectors.readAddress(string.concat(base, ".verifying_contract"))
        );
        assertEq(computed, vectors.readBytes32(string.concat(base, ".hash")));
    }

    function loadIntentFields(string memory f)
        internal
        view
        returns (HazeProtocolVectors.IntentFields memory fields)
    {
        fields.applicationId = vectors.readBytes32(string.concat(f, ".applicationId"));
        fields.user = vectors.readAddress(string.concat(f, ".user"));
        fields.pool = vectors.readAddress(string.concat(f, ".pool"));
        fields.poolVersion = vectors.readBytes32(string.concat(f, ".poolVersion"));
        fields.action = uint8(vectors.readUint(string.concat(f, ".action")));
        fields.noteTreeRoot = vectors.readUint(string.concat(f, ".noteTreeRoot"));
        fields.applicationPolicyVersion = uint64(vectors.readUint(string.concat(f, ".applicationPolicyVersion")));
        fields.hazePolicyVersion = uint64(vectors.readUint(string.concat(f, ".hazePolicyVersion")));
        fields.applicationMembershipRoot = vectors.readUint(string.concat(f, ".applicationMembershipRoot"));
        fields.hazeBlocklistRoot = vectors.readUint(string.concat(f, ".hazeBlocklistRoot"));
        fields.inputNullifier0 = vectors.readUint(string.concat(f, ".inputNullifier0"));
        fields.inputNullifier1 = vectors.readUint(string.concat(f, ".inputNullifier1"));
        fields.outputCommitment0 = vectors.readUint(string.concat(f, ".outputCommitment0"));
        fields.outputCommitment1 = vectors.readUint(string.concat(f, ".outputCommitment1"));
        fields.publicAmount = uint64(vectors.readUint(string.concat(f, ".publicAmount")));
        fields.publicRecipient = vectors.readAddress(string.concat(f, ".publicRecipient"));
        fields.recipientCiphertextHash0 = vectors.readBytes32(string.concat(f, ".recipientCiphertextHash0"));
        fields.recipientCiphertextHash1 = vectors.readBytes32(string.concat(f, ".recipientCiphertextHash1"));
        fields.auditDataCommitment = vectors.readUint(string.concat(f, ".auditDataCommitment"));
        fields.auditCiphertextHash = vectors.readBytes32(string.concat(f, ".auditCiphertextHash"));
        fields.tokenIn = vectors.readAddress(string.concat(f, ".tokenIn"));
        fields.amountIn = vectors.readUint(string.concat(f, ".amountIn"));
        fields.minUsdcOut = uint64(vectors.readUint(string.concat(f, ".minUsdcOut")));
        fields.routeHash = vectors.readBytes32(string.concat(f, ".routeHash"));
        fields.deadline = uint48(vectors.readUint(string.concat(f, ".deadline")));
    }

    function loadAuthorizationFields(string memory a)
        internal
        view
        returns (HazeProtocolVectors.AuthorizationFields memory fields)
    {
        fields.applicationId = vectors.readBytes32(string.concat(a, ".applicationId"));
        fields.user = vectors.readAddress(string.concat(a, ".user"));
        fields.pool = vectors.readAddress(string.concat(a, ".pool"));
        fields.poolVersion = vectors.readBytes32(string.concat(a, ".poolVersion"));
        fields.action = uint8(vectors.readUint(string.concat(a, ".action")));
        fields.intentHash = vectors.readBytes32(string.concat(a, ".intentHash"));
        fields.applicationPolicyVersion = uint64(vectors.readUint(string.concat(a, ".applicationPolicyVersion")));
        fields.hazePolicyVersion = uint64(vectors.readUint(string.concat(a, ".hazePolicyVersion")));
        fields.auditDataCommitment = vectors.readUint(string.concat(a, ".auditDataCommitment"));
        fields.auditCiphertextHash = vectors.readBytes32(string.concat(a, ".auditCiphertextHash"));
        fields.nonce = vectors.readBytes32(string.concat(a, ".nonce"));
        fields.validAfter = uint48(vectors.readUint(string.concat(a, ".validAfter")));
        fields.validUntil = uint48(vectors.readUint(string.concat(a, ".validUntil")));
    }

    function testIntentAndAuthorizationDigestsMatchCommittedArtifact() public view {
        string memory intentBase = positiveNamed("haze_intent_deposit");
        bytes32 intentStruct =
            HazeProtocolVectors.intentStructHash(loadIntentFields(string.concat(intentBase, ".fields")));
        assertEq(intentStruct, vectors.readBytes32(string.concat(intentBase, ".struct_hash")));

        string memory sepBase = positiveNamed("eip712_domain_separator_fuji");
        bytes32 separator = HazeProtocolVectors.domainSeparator(
            vectors.readString(string.concat(sepBase, ".name_string")),
            vectors.readString(string.concat(sepBase, ".version")),
            vectors.readUint(string.concat(sepBase, ".chain_id")),
            vectors.readAddress(string.concat(sepBase, ".verifying_contract"))
        );
        assertEq(
            HazeProtocolVectors.typedDataDigest(separator, intentStruct),
            vectors.readBytes32(string.concat(intentBase, ".digest"))
        );

        string memory authBase = positiveNamed("application_authorization");
        bytes32 authStruct = HazeProtocolVectors.authorizationStructHash(
            loadAuthorizationFields(string.concat(authBase, ".fields"))
        );
        assertEq(authStruct, vectors.readBytes32(string.concat(authBase, ".struct_hash")));
        assertEq(
            HazeProtocolVectors.typedDataDigest(separator, authStruct),
            vectors.readBytes32(string.concat(authBase, ".digest"))
        );
    }

    function testCommittedPolicySubjectHashesArePinned() public view {
        assertEq(
            vectors.readBytes32(string.concat(positiveNamed("application_member"), ".field")),
            hex"232c99b36cf639fce072561bbc8c85e6117dac9f74810ba9b0584114835219bd"
        );
        assertEq(
            vectors.readBytes32(string.concat(positiveNamed("global_blocked_note"), ".field")),
            hex"2e63a93984685f7a17285d895382a8cdebc6670135daa20a39173a181819df49"
        );
        assertEq(
            vectors.readBytes32(string.concat(positiveNamed("global_blocked_address"), ".field")),
            hex"0214dd05d5f2419fc8d72ed51c60128351ed72253014a98d9d0064decd2e41eb"
        );
    }
}
