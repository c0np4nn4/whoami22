// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "../contracts/E2EVess.sol";

interface LifecycleVm {
    function warp(uint256 time) external;
    function deal(address who, uint256 amount) external;
    function prank(address who) external;
}

/// Fixtures establish states normally produced by initialization, issuance and
/// record admission. The tests call the production reservation/dispute/DA
/// functions, including real BN254 reservation signature verification.
contract LifecycleHarness is E2EVess {
    bytes32 public constant SOURCE = keccak256("source");
    bytes32 public constant TARGET = keccak256("target");

    function seedRegistry() external {
        seedRegistrySize(8,8);
    }

    function seedRegistrySize(uint256 count,uint256 threshold) public {
        committeeN=4; committeeK=2; committeeF=1;
        currentState=SOURCE; stateT[SOURCE]=threshold;
        uint256 width=1;while(width<threshold)width*=2;
        bytes32[] memory layer=new bytes32[](width);
        for(uint256 l=0;l<threshold;l++)layer[l]=keccak256(abi.encodePacked(l,uint256(0),uint256(0)));
        while(width>1){for(uint256 l=0;l<width/2;l++)layer[l]=keccak256(abi.encodePacked(layer[2*l],layer[2*l+1]));width/=2;}
        for(uint256 i=1;i<=4;i++) {
            reservationKeys[i]=mul(base(),i+10);
            dealerKeys[i][0]=mul(base(),i+20);
            coefficientRoots[SOURCE].push(layer[0]);
        }
        for(uint256 i=1;i<=count;i++) {
            Pt memory pk=mul(base(),i+100);
            bytes32 registration=keccak256(abi.encodePacked("VESS-REGISTER-v1",SOURCE,i,pk.x,pk.y));
            (Pt memory r,uint256 s)=fixtureSign(i+100,registration);
            registry.registerParticipant(i,SOURCE,pk.x,pk.y,r.x,r.y,s);
            (bytes32 alpha,,,,,)=registry.activation(i);
            uint256[] memory attestations=new uint256[](14);
            for(uint256 j=1;j<=2;j++) {
                bytes32 issuance=keccak256(abi.encodePacked("VESS-ISSUANCE-v1",alpha,SOURCE,uint256(0),i,pk.x,pk.y,j,uint256(0),uint256(0),uint256(0)));
                (r,s)=fixtureSign(j+20,issuance);
                uint256 at=7*(j-1);attestations[at]=j;attestations[at+4]=r.x;attestations[at+5]=r.y;attestations[at+6]=s;
            }
            registry.activate(i,SOURCE,attestations,new uint256[](4*threshold));
        }
        require(population()==count&&pendingParticipants()==0,"fixture real registry completion");
    }

    function fixtureSign(uint256 sk,bytes32 message) internal view returns(Pt memory r,uint256 s) {
        Pt memory pk=mul(base(),sk);r=mul(base(),13);
        uint256 c=uint256(keccak256(abi.encodePacked("BN-SIG-v1",pk.x,pk.y,r.x,r.y,message)))%Q;
        s=addmod(13,mulmod(c,sk,Q),Q);
    }

    function seedIncoming(uint256 id,uint256 threshold) external {
        incomingOffline[SOURCE][id]=true;unionCount[SOURCE]++;stateT[SOURCE]=threshold;
    }

    function charges() external view returns(uint256 count,uint256 union_) {
        return(chargedCount[SOURCE],unionCount[SOURCE]);
    }

    function reservationSignatures(bytes32 target,uint256 nonce,uint256 threshold,bytes32 oldRoot,uint256[] memory off) external view returns(uint256[] memory sigs) {
        bytes32 recipientsHash=keccak256(abi.encodePacked(off));
        bytes32 nextRoot=keccak256(abi.encodePacked(oldRoot,recipientsHash,nonce,target));
        bytes32 message=keccak256(abi.encodePacked("RESERVE",SOURCE,target,nonce,threshold,population(),oldRoot,nextRoot,recipientsHash));
        sigs=new uint256[](12);
        for(uint256 i=1;i<=3;i++) {
            uint256 sk=i+10;Pt memory pk=mul(base(),sk);Pt memory r=mul(base(),13);
            uint256 c=uint256(keccak256(abi.encodePacked("BN-SIG-v1",pk.x,pk.y,r.x,r.y,message)))%Q;
            uint256 at=4*(i-1);sigs[at]=i;sigs[at+1]=r.x;sigs[at+2]=r.y;sigs[at+3]=addmod(13,mulmod(c,sk,Q),Q);
        }
    }

    function groupPoint(uint256 s) external view returns(uint256,uint256) {
        Pt memory p=mul(base(),s);return(p.x,p.y);
    }
}

contract E2EReleasePolicyTest {
    LifecycleVm constant vm=LifecycleVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    LifecycleHarness h;
    function setUp() public {
        h=new LifecycleHarness();h.configureReleasePolicy(1,16);h.seedRegistrySize(64,64);
    }
    function recipients(uint256 start,uint256 count) internal pure returns(uint256[] memory ids) {
        ids=new uint256[](count);for(uint256 i=0;i<count;i++)ids[i]=start+i;
    }
    function reserve(uint256 nonce,uint256 targetT,uint256[] memory off) internal returns(bool ok) {
        bytes32 target=keccak256(abi.encodePacked("policy-candidate",nonce));
        bytes32 old=h.releaseRoot(h.SOURCE());
        uint256[] memory sigs=h.reservationSignatures(target,nonce,targetT,old,off);
        (ok,)=address(h).call(abi.encodeCall(h.reserve,(h.SOURCE(),target,nonce,targetT,64,old,off,sigs)));
    }
    function testSixteenRecipientsUseConfiguredBudgetAndAnIncomingUnion() public {
        require(h.participantCorruptionBudget()==1&&h.outgoingRecipientBudget()==16,"configured policy");
        for(uint256 id=1;id<=16;id++)h.seedIncoming(id,34);
        require(reserve(1,64,recipients(1,16)),"16 repeated incoming recipients rejected");
        (uint256 charged_,uint256 union_)=h.charges();
        require(charged_==16&&union_==16,"incoming recipients double-counted");
    }
    function testTargetBoundIsStrictAndRejectionDoesNotChargeLedger() public {
        require(!reserve(1,33,recipients(1,16)),"delta + offline + outgoing reached threshold");
        (uint256 charged_,uint256 union_)=h.charges();
        require(charged_==0&&union_==0&&h.releaseRoot(h.SOURCE())==0,"rejected target mutated ledger");
        require(reserve(2,34,recipients(1,16)),"strictly admissible target rejected");
    }
    function testSourceBoundIncludesIncomingRecipientsOutsideOutgoingSet() public {
        h.seedIncoming(17,18);
        require(!reserve(1,64,recipients(1,16)),"source union reached threshold");
        (uint256 charged_,uint256 union_)=h.charges();
        require(charged_==0&&union_==1&&h.releaseRoot(h.SOURCE())==0,"source guard mutated ledger");
    }
    function testConfiguredOutgoingBudgetAccumulatesAcrossAborts() public {
        require(reserve(1,64,recipients(1,8)),"first group");h.abortEpoch(1);
        require(reserve(2,64,recipients(9,8)),"second group");h.abortEpoch(2);
        bytes32 old=h.releaseRoot(h.SOURCE());
        require(!reserve(3,64,recipients(17,1)),"17th distinct recipient accepted");
        require(h.releaseRoot(h.SOURCE())==old,"rejected extra recipient mutated root");
        require(reserve(4,64,recipients(1,16)),"same recipients charged twice after abort");
        (uint256 charged_,uint256 union_)=h.charges();require(charged_==16&&union_==16,"durable charges lost");
    }
    function testPolicyCannotChangeAfterInitialState() public {
        (bool ok,)=address(h).call(abi.encodeCall(h.configureReleasePolicy,(0,64)));
        require(!ok&&h.participantCorruptionBudget()==1&&h.outgoingRecipientBudget()==16,"policy changed after bootstrap");
    }
    function testOnlyAdministratorCanChoosePolicy() public {
        E2EVess fresh=new E2EVess();vm.prank(address(7));
        (bool ok,)=address(fresh).call(abi.encodeCall(fresh.configureReleasePolicy,(1,16)));
        require(!ok,"unauthorized policy configuration");
        require(fresh.participantCorruptionBudget()==1&&fresh.outgoingRecipientBudget()==2,"default legacy policy");
        fresh.configureReleasePolicy(2,16);
        require(fresh.participantCorruptionBudget()==2&&fresh.outgoingRecipientBudget()==16,"admin policy rejected");
    }
}

contract E2EReservationTest {
    LifecycleHarness h;
    function setUp() public {h=new LifecycleHarness();h.seedRegistry();}
    function off(uint256 a) internal pure returns(uint256[] memory v) {v=new uint256[](1);v[0]=a;}
    function off(uint256 a,uint256 b) internal pure returns(uint256[] memory v) {v=new uint256[](2);v[0]=a;v[1]=b;}
    function reserve(uint256 nonce,uint256[] memory recipients,bytes32 oldRoot) internal returns(bool ok) {
        bytes32 target=keccak256(abi.encodePacked("candidate",nonce));
        uint256[] memory sigs=h.reservationSignatures(target,nonce,6,oldRoot,recipients);
        (ok,)=address(h).call(abi.encodeCall(h.reserve,(h.SOURCE(),target,nonce,6,8,oldRoot,recipients,sigs)));
    }

    function testSameAttemptExtendsBeforeReleaseAndCannotRemoveRecipient() public {
        require(reserve(1,off(1),bytes32(0)),"first reserve");
        bytes32 first=h.releaseRoot(h.SOURCE());
        require(!reserve(1,off(2,3),first),"removed public recipient");
        require(h.releaseRoot(h.SOURCE())==first,"failed extension mutated root");
        require(reserve(1,off(1,2),first),"same-attempt reclassification");
        (uint256 charged_,uint256 union_)=h.charges();
        require(charged_==2&&union_==2,"extension charged incorrect union");
        require(h.releaseRoot(h.SOURCE())!=first,"extension root unchanged");
    }

    function testAbortRetainsChargesAndDisjointRetryExhaustsBudget() public {
        require(reserve(1,off(1),bytes32(0)),"first reserve");
        bytes32 first=h.releaseRoot(h.SOURCE());h.abortEpoch(1);
        require(h.releaseRoot(h.SOURCE())==first,"abort erased ledger");
        require(reserve(2,off(2),first),"second recipient reserve");
        bytes32 second=h.releaseRoot(h.SOURCE());h.abortEpoch(2);
        require(!reserve(3,off(3),second),"third distinct recipient exceeded cap");
        require(h.releaseRoot(h.SOURCE())==second,"rejected reservation mutated ledger");
        require(reserve(4,off(1),second),"same recipient retry double-charged");
        (uint256 charged_,uint256 union_)=h.charges();
        require(charged_==2&&union_==2,"durable union changed on retry");
    }

    function testStaleCASAndDuplicateRecipientsRejectedAtomically() public {
        require(reserve(1,off(1),bytes32(0)),"first reserve");
        bytes32 first=h.releaseRoot(h.SOURCE());
        require(!reserve(2,off(2),bytes32(0)),"stale CAS accepted");
        require(!reserve(2,off(2,2),first),"duplicate recipients accepted");
        require(h.releaseRoot(h.SOURCE())==first,"rejected request mutated root");
    }

    function testIncomingAndOutgoingExposureUseAUnion() public {
        h.seedIncoming(1,4);
        require(reserve(1,off(1),bytes32(0)),"incoming recipient counted twice");
        require(reserve(2,off(2),h.releaseRoot(h.SOURCE())),"union of two should pass");
        (uint256 charged_,uint256 union_)=h.charges();
        require(charged_==2&&union_==2,"incoming/outgoing union incorrect");
    }

    function testSourceGuardRejectsBeforeAnyDurableMutation() public {
        h.seedIncoming(3,4);
        require(!reserve(1,off(1,2),bytes32(0)),"source exposure reached threshold");
        (uint256 charged_,uint256 union_)=h.charges();
        require(charged_==0&&union_==1&&h.releaseRoot(h.SOURCE())==0,"failed guard charged source");
    }

    function testReservationRequiresDistinctQuorumSigners() public {
        uint256[] memory recipients=off(1);bytes32 target=keccak256("candidate");
        uint256[] memory sigs=h.reservationSignatures(target,1,6,bytes32(0),recipients);
        for(uint256 i=0;i<4;i++)sigs[8+i]=sigs[i];
        (bool ok,)=address(h).call(abi.encodeCall(h.reserve,(h.SOURCE(),target,1,6,8,bytes32(0),recipients,sigs)));
        require(!ok,"duplicate signer counted toward quorum");
    }
}
