// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {DevelopmentEqualityVerifier} from "haze-dev/DevelopmentEqualityVerifier.sol";

contract CeremonyTest is Test {
    using stdJson for string;

    DevelopmentEqualityVerifier internal verifier;

    function setUp() public {
        verifier = new DevelopmentEqualityVerifier();
    }

    function testDevelopmentVerifierIsNotForProduction() public view {
        assertTrue(verifier.NOT_FOR_PRODUCTION());
    }

    function testEqualityProofPassesOnlyWhenValuesAndArtifactMatch() public view {
        bytes32 artifactHash = verifier.ARTIFACT_HASH();
        assertTrue(verifier.verify(7, 7, artifactHash));
        assertFalse(verifier.verify(7, 8, artifactHash));
    }

    function testWrongArtifactHashReverts() public {
        vm.expectRevert(bytes("ARTIFACT"));
        verifier.verify(7, 7, bytes32(uint256(1)));
    }

    function testProvenanceKeepsSc09GatesClosed() public view {
        string memory raw = vm.readFile(string.concat(vm.projectRoot(), "/../dev/artifacts/provenance.json"));
        assertFalse(raw.readBool(".sc09.fuji_pilot.approved"));
        assertFalse(raw.readBool(".sc09.independent_audit.approved"));
        assertFalse(raw.readBool(".sc09.production_ceremony.approved"));
        assertFalse(raw.readBool(".sc09.incident_review.approved"));
        assertEq(raw.readString(".spend_prove"), "KEYS_MISSING");
    }
}
