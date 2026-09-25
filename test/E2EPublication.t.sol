// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;
import "../contracts/E2EVess.sol";
import "./E2ELifecycle.t.sol";

interface PublicationVm {
    function blobhashes(bytes32[] calldata hashes) external;
    function mockCall(address callee, bytes calldata data, bytes calldata result) external;
}
contract PublicationHarness is E2EVess {
    // Isolate publication/commit gating from reservation signature tests.
    function seed() external { committeeN=1; attempts[1].status=1; }
}
contract E2EPublicationTest {
    PublicationVm constant vm=PublicationVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 constant ROOT=bytes32(uint256(42));
    bytes32 constant META=bytes32(uint256(7));
    PublicationHarness h;
    E2EPublication store;
    function setUp() public {
        h=new PublicationHarness();store=new E2EPublication(address(h));h.setPublicationStore(store);h.seed();
    }
    function proofs(uint256 start,uint256 count) internal returns(bytes memory out) {
        bytes32[] memory hashes=new bytes32[](count);
        for(uint256 i;i<count;i++) {
            hashes[i]=bytes32(uint256(0x010000)+start+i);
            bytes memory proof=abi.encodePacked(hashes[i],uint256(1),ROOT,new bytes(96));
            vm.mockCall(address(10),proof,abi.encode(uint256(4096),uint256(52435875175126190479447740508185965837690552500527637822603658699938581184513)));
            out=bytes.concat(out,proof);
        }
        vm.blobhashes(hashes);
    }
    function publish(uint256 length,uint256 offset,bytes memory p,bytes32 root) internal returns(bool ok) {
        bytes32[] memory roots=new bytes32[](1);
        (ok,)=address(h).call(abi.encodeCall(h.publish,(1,root,META,roots,length,offset,p)));
    }
    function status() internal view returns(uint256 s) {(,,,,,s)=h.publication(1);}
    function testTenBlobsRequireBothBatchesAndCannotCommitPartial() public {
        uint256 length=9*store.PAYLOAD_BYTES()+1;
        require(publish(length,0,proofs(0,9),ROOT),"first batch");
        require(status()==1,"partial marked published");
        (bool ok,)=address(h).call(abi.encodeCall(h.commitEpoch,(1,new uint256[](0))));
        require(!ok,"committed incomplete bundle");
        require(publish(length,9,proofs(9,1),ROOT),"last batch");
        require(status()==2,"complete not published");
        (,,bytes32 first,,,)=h.publication(1);
        require(first==store.versionAt(1,0),"root admission anchor changed");
        require(!publish(length,9,proofs(9,1),ROOT),"duplicate final batch");
    }
    function testRejectOffsetReplayChangedIdentityAndWrongBlobRoot() public {
        uint256 length=store.PAYLOAD_BYTES()+1;
        require(publish(length,0,proofs(0,1),ROOT),"first");
        require(!publish(length,0,proofs(0,1),ROOT),"replay");
        require(!publish(length,2,proofs(1,1),ROOT),"gap");
        require(!publish(length+1,1,proofs(1,1),ROOT),"changed length");
        bytes32[] memory roots=new bytes32[](1);
        (bool changed,)=address(h).call(abi.encodeCall(h.publish,(1,ROOT,bytes32(uint256(8)),roots,length,1,proofs(1,1))));
        require(!changed,"changed manifest digest");
        require(!publish(length,1,proofs(1,1),bytes32(uint256(43))),"changed root");
        bytes memory bad=proofs(1,1);bad[95]=bytes1(uint8(43));
        require(!publish(length,1,bad,ROOT),"wrong opening root");
        require(publish(length,1,proofs(1,1),ROOT),"valid retry");
    }
    function testRejectMissingExtraAndUnrelatedBlobs() public {
        bytes memory p=proofs(0,2);
        require(!publish(1,0,p,ROOT),"extra fragments");
        bytes memory one=new bytes(192);for(uint256 i;i<192;i++)one[i]=p[i];
        require(!publish(1,0,one,ROOT),"extra transaction blob");
        proofs(5,1);
        require(!publish(1,0,one,ROOT),"unrelated transaction hash");
        vm.blobhashes(new bytes32[](0));
        require(!publish(1,0,one,ROOT),"absent sidecar");
    }
    function testAbortPartialPublicationCannotResume() public {
        uint256 length=store.PAYLOAD_BYTES()+1;
        require(publish(length,0,proofs(0,1),ROOT),"first");
        h.abortEpoch(1);
        require(!publish(length,1,proofs(1,1),ROOT),"resumed aborted publication");
        require(store.versionAt(1,0)!=0,"aborted exposure deleted");
    }
    function testStoreCannotBeReplacedOrWrittenDirectly() public {
        (bool ok,)=address(h).call(abi.encodeCall(h.setPublicationStore,(store)));
        require(!ok,"replaced store");
        (ok,)=address(store).call(abi.encodeCall(store.append,(1,ROOT,META,1,0,proofs(0,1))));
        require(!ok,"untrusted writer");
    }
}

contract PublicationReservationTest {
    PublicationVm constant vm=PublicationVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    function testReservationCannotExtendAfterFirstPublicationBatch() public {
        LifecycleHarness h=new LifecycleHarness();h.seedRegistry();
        E2EPublication store=new E2EPublication(address(h));h.setPublicationStore(store);
        uint256[] memory off=new uint256[](1);off[0]=1;
        h.reserve(h.SOURCE(),h.TARGET(),1,6,8,bytes32(0),off,h.reservationSignatures(h.TARGET(),1,6,bytes32(0),off));
        bytes32 reserved=h.releaseRoot(h.SOURCE());
        bytes32[] memory hashes=new bytes32[](1);hashes[0]=bytes32(uint256(0x010123));vm.blobhashes(hashes);
        bytes memory proof=abi.encodePacked(hashes[0],uint256(1),uint256(42),new bytes(96));
        vm.mockCall(address(10),proof,abi.encode(uint256(4096),uint256(52435875175126190479447740508185965837690552500527637822603658699938581184513)));
        h.publish(1,bytes32(uint256(42)),bytes32(uint256(7)),new bytes32[](4),store.PAYLOAD_BYTES()+1,0,proof);
        off=new uint256[](2);off[0]=1;off[1]=2;
        (bool ok,)=address(h).call(abi.encodeCall(h.reserve,(h.SOURCE(),h.TARGET(),1,6,8,reserved,off,h.reservationSignatures(h.TARGET(),1,6,reserved,off))));
        require(!ok&&h.releaseRoot(h.SOURCE())==reserved,"reservation changed during multipart release");
    }
}
