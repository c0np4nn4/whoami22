// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;
import "../contracts/E2EVess.sol";

interface IssuanceVm { function warp(uint256) external; }

/// Executable registry conformance checks, without a mock signature verifier.
contract IssuanceTest {
    uint256 constant Q=21888242871839275222246405745257275088548364400416034343698204186575808495617;
    IssuanceVm constant vm=IssuanceVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    E2EVess registry;
    bytes32 constant STATE=keccak256("issuance-test-public-state");
    struct P {uint256 x;uint256 y;}
    function point(uint256 scalar) internal view returns(P memory p){
        uint256[3] memory args=[uint256(1),2,scalar];bool ok;
        assembly("memory-safe"){ok:=staticcall(gas(),7,args,96,p,64)}require(ok);
    }
    function coefficient(uint256 dealer,uint256 index) internal pure returns(uint256){return 17+index+(3+index)*dealer;}
    function vector(uint256 dealer) internal view returns(uint256[] memory values,bytes32 root){
        values=new uint256[](8);bytes32[4] memory leaves;
        for(uint256 l=0;l<4;l++){P memory p=point(coefficient(dealer,l));values[2*l]=p.x;values[2*l+1]=p.y;leaves[l]=keccak256(abi.encodePacked(l,p.x,p.y));}
        root=keccak256(abi.encodePacked(keccak256(abi.encodePacked(leaves[0],leaves[1])),keccak256(abi.encodePacked(leaves[2],leaves[3]))));
    }
    function registration(uint256 id,uint256 sk) internal view returns(bytes memory){
        P memory pk=point(sk);P memory r=point(71);
        bytes32 message=keccak256(abi.encodePacked("VESS-REGISTER-v1",STATE,id,pk.x,pk.y));
        uint256 c=uint256(keccak256(abi.encodePacked("BN-SIG-v1",pk.x,pk.y,r.x,r.y,message)))%Q;
        return abi.encodeCall(registry.registerParticipant,(id,STATE,pk.x,pk.y,r.x,r.y,addmod(71,mulmod(c,sk,Q),Q)));
    }
    function setUp() public {
        registry=new E2EVess();uint256[] memory keys=new uint256[](16);bytes32[] memory roots=new bytes32[](4);
        for(uint256 j=1;j<=4;j++){
            P memory p=point(11+j);registry.register(j,0,p.x,p.y,address(this));
            keys[(j-1)*4]=p.x;keys[(j-1)*4+1]=p.y;keys[(j-1)*4+2]=p.x;keys[(j-1)*4+3]=p.y;
            (,roots[j-1])=vector(j);
        }
        registry.bootstrap(STATE,0,4,4,2,1,keys,roots);
        (bool ok,)=address(registry).call(registration(9,42));require(ok,"registration fixture");
    }
    function certificate() internal view returns(uint256[] memory signatures,uint256[] memory vectors){
        signatures=new uint256[](14);vectors=new uint256[](16);
        (bytes32 alpha,,,,uint256 px,uint256 py)=registry.activation(9);
        for(uint256 j=1;j<=2;j++){
            (uint256[] memory v,)=vector(j);for(uint256 l=0;l<8;l++)vectors[(j-1)*8+l]=v[l];
            uint256 scalar;uint256 power=1;
            for(uint256 l=0;l<4;l++){scalar=addmod(scalar,mulmod(coefficient(j,l),power,Q),Q);power=mulmod(power,9,Q);}
            P memory e=point(scalar);P memory r=point(100+j);P memory pk=point(11+j);
            bytes32 message=keccak256(abi.encodePacked("VESS-ISSUANCE-v1",alpha,STATE,uint256(0),uint256(9),px,py,j,uint256(0),e.x,e.y));
            uint256 c=uint256(keccak256(abi.encodePacked("BN-SIG-v1",pk.x,pk.y,r.x,r.y,message)))%Q;
            uint256 at=(j-1)*7;signatures[at]=j;signatures[at+1]=0;signatures[at+2]=e.x;signatures[at+3]=e.y;
            signatures[at+4]=r.x;signatures[at+5]=r.y;signatures[at+6]=addmod(100+j,mulmod(c,11+j,Q),Q);
        }
    }
    function attempt(uint256[] memory sigs,uint256[] memory vectors) internal returns(bool ok){
        (ok,)=address(registry).call(abi.encodeCall(registry.activate,(9,STATE,sigs,vectors)));
    }
    function testCertificateCompletesPublicRegistryWithoutShareScalars() public {
        (uint256[] memory sigs,uint256[] memory vectors)=certificate();require(attempt(sigs,vectors));
        require(registry.activeParticipant(9)&&registry.population()==1&&registry.pendingParticipants()==0);
        uint256[] memory ids=registry.eligibleParticipants();require(ids.length==1&&ids[0]==9,"actual identifier set");
        require(!attempt(sigs,vectors),"duplicate completion accepted");
    }
    function testDeploymentSizeAndRegistryControllerBoundary() public {
        require(address(registry).code.length<=24576,"lifecycle EIP-170 size");
        require(type(E2EVess).creationCode.length<=49152,"lifecycle EIP-3860 initcode size");
        E2ERegistry module=registry.registry();
        require(address(module).code.length>0&&address(module).code.length<=24576,"registry EIP-170 size");
        (uint256[] memory sigs,uint256[] memory vectors)=certificate();
        (bool ok,)=address(module).call(abi.encodeCall(module.activate,(9,STATE,sigs,vectors)));
        require(!ok,"module controller bypass");require(attempt(sigs,vectors),"forwarded valid certificate");
        (ok,)=address(module).call(abi.encodeCall(module.beginRecovery,(9)));
        require(!ok&&registry.activeParticipant(9),"direct recovery bypass");
        (ok,)=address(module).call(registration(10,43));require(!ok,"direct registration bypass");
    }
    function testReleasePolicyCannotChangeAfterBootstrap() public {
        (bool ok,)=address(registry).call(abi.encodeCall(registry.configureReleasePolicy,(0,16)));
        require(!ok&&registry.participantCorruptionBudget()==1&&registry.outgoingRecipientBudget()==2,"bootstrapped release policy changed");
    }
    function testInitialThresholdChecksCorruptionWithoutChargingFutureRecipients() public {
        E2EVess fresh=new E2EVess();fresh.configureReleasePolicy(1,16);
        uint256[] memory keys=new uint256[](16);bytes32[] memory roots=new bytes32[](4);
        for(uint256 j=1;j<=4;j++) {
            P memory p=point(11+j);fresh.register(j,0,p.x,p.y,address(this));
            keys[(j-1)*4]=p.x;keys[(j-1)*4+1]=p.y;keys[(j-1)*4+2]=p.x;keys[(j-1)*4+3]=p.y;
        }
        (bool ok,)=address(fresh).call(abi.encodeCall(fresh.bootstrap,(STATE,0,1,4,2,1,keys,roots)));
        require(!ok&&fresh.currentState()==0,"initial exposure reached threshold");
        fresh.bootstrap(STATE,0,2,4,2,1,keys,roots);
        require(fresh.stateT(STATE)==2,"empty initial exposure incorrectly charged future recipient budget");
    }
    function testRejectsDuplicateSignerTamperedVectorAndSignature() public {
        (uint256[] memory sigs,uint256[] memory vectors)=certificate();sigs[7]=1;require(!attempt(sigs,vectors),"duplicate dealer");
        (sigs,vectors)=certificate();vectors[0]=1;vectors[1]=2;require(!attempt(sigs,vectors),"unanchored vector");
        (sigs,vectors)=certificate();sigs[6]=addmod(sigs[6],1,Q);require(!attempt(sigs,vectors),"forged attestation");
        (sigs,vectors)=certificate();sigs[2]=1;sigs[3]=2;require(!attempt(sigs,vectors),"wrong evaluation");
    }
    function testRecoveryGetsFreshActivationAndRejectsPriorCertificate() public {
        (uint256[] memory old,uint256[] memory vectors)=certificate();require(attempt(old,vectors));
        (bytes32 alpha,,,,,)=registry.activation(9);registry.beginRecovery(9);
        (bytes32 fresh,,,,,)=registry.activation(9);require(alpha!=fresh&&!registry.activeParticipant(9));
        require(registry.eligibleParticipants().length==0,"recovery-pending member eligible");
        require(!attempt(old,vectors),"old activation replay");
        (uint256[] memory sigs,)=certificate();require(attempt(sigs,vectors));require(registry.population()==1);
    }
    function testRejectsInsufficientCertificateWrongEpochAndUnreservedRecipient() public {
        (uint256[] memory sigs,uint256[] memory vectors)=certificate();
        uint256[] memory one=new uint256[](7);uint256[] memory v=new uint256[](8);
        for(uint256 l=0;l<7;l++)one[l]=sigs[l];for(uint256 l=0;l<8;l++)v[l]=vectors[l];
        require(!attempt(one,v),"insufficient dealers");
        (bool ok,)=address(registry).call(abi.encodeCall(registry.activate,(10,STATE,sigs,vectors)));require(!ok,"unreserved recipient");
        (ok,)=address(registry).call(abi.encodeCall(registry.activate,(9,bytes32(uint256(7)),sigs,vectors)));require(!ok,"wrong state");
        sigs[1]=1;require(!attempt(sigs,vectors),"wrong signing epoch");
    }
    function testIdenticalRetryDoesNotDoubleChargeAndConflictsFail() public {
        (bytes32 alpha,,,,,)=registry.activation(9);(bool ok,)=address(registry).call(registration(9,42));require(ok,"identical retry");
        (bytes32 retry,,,,,)=registry.activation(9);require(alpha==retry&&registry.pendingParticipants()==1);
        (ok,)=address(registry).call(registration(10,42));require(!ok,"key reused");
        (ok,)=address(registry).call(registration(9,43));require(!ok,"identifier reused");
    }
    function testRegistrationProofBindsRecipientKeyAndState() public {
        bytes memory proof=registration(10,43);proof[proof.length-1]^=0x01;
        (bool ok,)=address(registry).call(proof);require(!ok,"forged registration proof");
        proof=registration(10,43);proof[35]=0x0b;
        (ok,)=address(registry).call(proof);require(!ok,"proof for another recipient");
        proof=registration(10,43);proof[67]^=0x01;
        (ok,)=address(registry).call(proof);require(!ok,"proof for another state");
        (ok,)=address(registry).call(registration(10,43));require(ok,"valid proof of possession");
    }
    function testExpirationUnblocksTransitionAndRejectsLateCompletion() public {
        (uint256[] memory sigs,uint256[] memory vectors)=certificate();vm.warp(block.timestamp+3601);
        require(!attempt(sigs,vectors),"expired completion");registry.expireActivation(9);
        require(registry.pendingParticipants()==0&&registry.population()==0);
    }
}
