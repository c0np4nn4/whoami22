// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "../contracts/E2EVess.sol";

interface AnchorVm {
    function mockCall(address callee, bytes calldata data, bytes calldata result) external;
}

contract AnchorHarness is E2EVess {
    function verifyAnchor(bytes32 expectedRoot, bytes32 expectedVersion, bytes calldata p0, bytes calldata p1) external view {
        rootOpeningFor(expectedRoot, expectedVersion, p0, p1);
    }
}

/// These tests isolate anchor wiring from KZG arithmetic. The real precompile
/// is exercised with actual blob proofs in every E2E publish transaction.
contract E2EAnchorTest {
    AnchorVm constant vm = AnchorVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant BLS = 52435875175126190479447740508185965837690552500527637822603658699938581184513;
    bytes32 constant VERSION = bytes32(uint256(0x010123));
    bytes32 constant ROOT = bytes32(uint256(42));
    AnchorHarness harness;
    bytes p0;
    bytes p1;

    function setUp() public {
        harness = new AnchorHarness();
        harness.setPublicationStore(new E2EPublication(address(harness)));
        p0 = abi.encodePacked(VERSION, uint256(1), uint256(42), new bytes(96));
        p1 = new bytes(0);
        vm.mockCall(address(10), p0, abi.encode(uint256(4096), BLS));
    }

    function accepts(bytes32 root_, bytes32 version_, bytes memory left, bytes memory right) internal view returns (bool ok) {
        (ok,) = address(harness).staticcall(abi.encodeCall(harness.verifyAnchor, (root_, version_, left, right)));
    }

    function testExactNativeAnchorAccepted() public view {
        require(accepts(ROOT, VERSION, p0, p1), "valid root binding");
    }

    function testRecordHashToCurveRetainsCanonicalVectors() public view {
        E2EPublication store=harness.publicationStore();
        (uint256 x,uint256 y)=store.hashPoint(bytes32(0));
        require(x==1&&y==2,"zero-seed rejection sampling");
        (x,y)=store.hashPoint(bytes32(uint256(42)));
        require(x==44&&y==15714383356257300717909548189289650942590685741732533144532885524333983437486,"two rejected candidates");
        (x,y)=store.hashPoint(bytes32(type(uint256).max));
        require(x==6350874878119819312338956282401532409788428879151445726012394534686998597020&&y==9382425333525343773979589293970912874995880615911074345993039062358358671562,"seed reduction and even-root convention");
    }

    function testUnrelatedBlobVersionRejected() public view {
        require(!accepts(ROOT, bytes32(uint256(VERSION) + 1), p0, p1), "unrelated blob accepted");
    }

    function testCalldataRootMustEqualBlobRoot() public view {
        require(!accepts(bytes32(uint256(ROOT) + 1), VERSION, p0, p1), "unrelated root accepted");
    }

    function testReversedAndTruncatedOpeningsRejected() public view {
        require(!accepts(ROOT, VERSION, p1, p0), "reversed root slots accepted");
        require(!accepts(ROOT, VERSION, new bytes(0), p1), "missing proof accepted");
    }

    function testNoncanonicalFieldRootRejected() public {
        bytes memory oversized = abi.encodePacked(VERSION, uint256(1), uint256(1) << 248, new bytes(96));
        vm.mockCall(address(10), oversized, abi.encode(uint256(4096), BLS));
        require(!accepts(ROOT, VERSION, oversized, p1), "oversized field root accepted");
    }
}
