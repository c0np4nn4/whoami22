// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;
import "../contracts/E2EDisputes.sol";

interface DisputeVm {function warp(uint256) external;function deal(address,uint256) external;function prank(address) external;}
/// Cryptographic verifiers are represented by controlled verdicts here. Real
/// BN254/signature/blob verification is covered by lifecycle and native E2E runs;
/// these tests isolate adversarial game ordering and exact economic settlement.
contract E2EDisputesTest {
    DisputeVm constant vm=DisputeVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant DEALER=address(0x1234);address constant CHALLENGER=address(0x2345);
    bytes32 constant ID=keccak256("admitted record");
    uint256 constant P=21888242871839275222246405745257275088696311157297823662689037894645226208583;
    E2EDisputes d;DisputeContext ctx;
    bool admissionGood=true;bool possessionGood=true;bool proofGood=true;bool plainGood=true;bool authGood=true;
    function setUp() public {
        d=new E2EDisputes(address(this));ctx.account=DEALER;ctx.required=true;ctx.expiry=block.timestamp+3600;ctx.ts=2;ctx.tt=2;ctx.n=4;
        vm.deal(address(this),10000);d.deposit{value:200}(DEALER);d.deposit{value:200}(CHALLENGER);
    }
    function dealerAccount(uint256) external pure returns(address){return DEALER;}
    function verifyRecord(uint256[] calldata,uint256,bytes32[] calldata,bytes calldata,bytes calldata) external view returns(bytes32){require(admissionGood,"bad signature/anchor");return ID;}
    function pop(uint256[] calldata) external view returns(bool){return possessionGood;}
    function verifyPlaintext(uint256[] calldata,uint256[] calldata) external view returns(bool,bool){return(proofGood,plainGood);}
    function disputeContext(uint256 nonce,uint256 dealer,uint256) external view returns(DisputeContext memory){require(nonce==1&&dealer==1,"unknown finalization");return ctx;}
    function verifyDA(address,uint256,uint256,uint256,uint256,uint256,uint256) external view returns(bool){return authGood;}
    function verifyDAResponse(uint256 nonce,uint256 dealer,uint256 recipient,bytes calldata raw,uint256,bytes32[] calldata) external pure returns(bool){return nonce==1&&dealer==1&&recipient==1&&keccak256(raw)==keccak256("anchored bytes");}
    function member(bytes32 root_,bytes32 leaf_,uint256 index,bytes32[] calldata path) external pure returns(bool){bytes32 v=leaf_;for(uint256 i=0;i<path.length;i++){v=index%2==0?keccak256(abi.encodePacked(v,path[i])):keccak256(abi.encodePacked(path[i],v));index/=2;}return index==0&&v==root_;}
    function fieldHash(bytes memory data) external pure returns(bytes32){return bytes32(uint256(keccak256(data))&((uint256(1)<<248)-1));}
    function recordMember(bytes32,bytes32,uint256,bytes32[] calldata) external pure returns(bool){return true;}
    function record() internal pure returns(uint256[] memory r){r=new uint256[](25);r[0]=1;r[1]=1;r[2]=1;r[10]=1;r[11]=P-2;}
    function admit() internal {d.admitRecord(record(),0,new bytes32[](0),"","");}
    function leaf(uint256 i,uint256 x,uint256 y) internal pure returns(bytes32){return keccak256(abi.encodePacked(i,x,y));}
    function trace(uint256 endY) internal pure returns(bytes32 root_,bytes32[] memory p0,bytes32[] memory p1,bytes32[] memory p2){
        bytes32 l0=leaf(0,0,0);bytes32 l1=leaf(1,1,2);bytes32 l2=leaf(2,1,endY);
        bytes32 left=keccak256(abi.encodePacked(l0,l1));bytes32 right=keccak256(abi.encodePacked(l2,bytes32(0)));root_=keccak256(abi.encodePacked(left,right));
        p0=new bytes32[](2);p1=new bytes32[](2);p2=new bytes32[](2);p0[0]=l1;p0[1]=right;p1[0]=l0;p1[1]=right;p2[1]=left;
    }
    function begin() internal {admit();(bytes32 rc,bytes32[] memory c0,,bytes32[] memory ct)=trace(2);d.beginGame(CHALLENGER,ID,rc,1,2,c0,ct);}
    function respond() internal {(bytes32 rd,bytes32[] memory d0,,bytes32[] memory dt)=trace(P-2);d.respondGame(DEALER,rd,d0,dt);}
    function key() internal view returns(bytes32){return d.obligationKey(1,1,1);}
    function open() internal {d.openDA{value:15}(CHALLENGER,1,1,1,0,0,0);}

    function testBadPossessionIsAdmittedThenChargedToSigningDealerOnce() public {
        possessionGood=false;admit();require(d.admitted(ID),"PoP incorrectly part of admission");
        d.plaintext{value:5}(CHALLENGER,record(),new uint256[](0),0,new bytes32[](0),"","");
        require(d.stake(DEALER)==190&&d.credit(CHALLENGER)==9&&d.plaintextSettled(ID),"bad PoP attribution");
        (bool twice,)=address(d).call{value:5}(abi.encodeCall(d.plaintext,(CHALLENGER,record(),new uint256[](0),0,new bytes32[](0),bytes(""),bytes(""))));require(!twice,"record penalized twice");
    }
    function testAdmissionFailureForfeitsClaimantBondWithoutChargingDealer() public {
        admissionGood=false;d.plaintext{value:5}(CHALLENGER,record(),new uint256[](0),0,new bytes32[](0),"","");
        require(d.stake(DEALER)==200&&d.credit(DEALER)==5&&d.forfeited()==5&&!d.admitted(ID),"invalid evidence settlement");
    }
    function testInvalidDecryptionProofForfeitsBondAndDoesNotBlockValidComplaint() public {
        proofGood=false;d.plaintext{value:5}(CHALLENGER,record(),new uint256[](0),0,new bytes32[](0),"","");
        require(d.credit(DEALER)==5&&d.stake(DEALER)==200&&!d.plaintextSettled(ID),"invalid decryption settlement");
        proofGood=true;plainGood=false;d.plaintext{value:5}(CHALLENGER,record(),new uint256[](0),0,new bytes32[](0),"","");require(d.stake(DEALER)==190,"valid complaint blocked");
    }
    function testChallengerCannotSupplyDealerTraceOrMoveBeforeResponse() public {
        begin();(bytes32 rd,bytes32[] memory p0,bytes32[] memory p1,bytes32[] memory pt)=trace(P-2);
        (bool impersonation,)=address(d).call(abi.encodeCall(d.respondGame,(CHALLENGER,rd,p0,pt)));require(!impersonation,"challenger authenticated dealer trace");
        (bool early,)=address(d).call(abi.encodeCall(d.move,(CHALLENGER,1,2,p1)));require(!early,"bisection before endpoints");
    }
    function testDealerInitialResponseTimeoutAndReplayPrevention() public {
        begin();vm.warp(block.timestamp+61);d.gameTimeout();require(d.credit(CHALLENGER)==10&&d.credit(DEALER)==0,"missing dealer endpoints not attributed");
        (bool twice,)=address(d).call(abi.encodeCall(d.gameTimeout,()));require(!twice,"double timeout");
        (bytes32 rc,bytes32[] memory c0,,bytes32[] memory ct)=trace(2);
        (bool replay,)=address(d).call(abi.encodeCall(d.beginGame,(CHALLENGER,ID,rc,1,2,c0,ct)));require(!replay,"repeat game on adjudicated record");
    }
    function testCopyingChallengerRootWithDifferentEndpointLosesDealerDeposit() public {
        begin();(bytes32 rc,bytes32[] memory c0,,bytes32[] memory ct)=trace(2);d.respondGame(DEALER,rc,c0,ct);
        require(d.credit(CHALLENGER)==10&&d.consistencySettled(ID),"copied root forged endpoint");
    }
    function testChallengerTimeoutAfterDealerEndpointsPaysDealer() public {
        begin();respond();vm.warp(block.timestamp+61);d.gameTimeout();require(d.credit(DEALER)==10,"wrong waiting party");
    }
    function testDealerTimeoutAfterChallengerMidpointPaysChallenger() public {
        begin();respond();(,,bytes32[] memory midpoint,)=trace(2);d.move(CHALLENGER,1,2,midpoint);vm.warp(block.timestamp+61);d.gameTimeout();require(d.credit(CHALLENGER)==10,"wrong waiting party");
    }
    function testNonzeroProtocolDeadlinesRequired() public {
        (bool zeroRound,)=address(d).call(abi.encodeCall(d.configure,(0,60,3600)));require(!zeroRound,"zero round deadline");
        (bool zeroResponse,)=address(d).call(abi.encodeCall(d.configure,(60,0,3600)));require(!zeroResponse,"zero response deadline");
    }
    function testMissingRecordCanBeChallengedWithoutAdmissionOrRecordBytes() public {
        require(!d.admitted(ID),"unexpected record");open();require(d.stake(DEALER)==100,"finalized obligation not escrowed");
        vm.warp(block.timestamp+61);d.defaultDA(key());require(d.credit(CHALLENGER)==55&&d.finderPaid()==40&&d.burned()==60,"default fee/slash incorrect");
        (bool twice,)=address(d).call(abi.encodeCall(d.defaultDA,(key())));require(!twice,"double default");
    }
    function testAnchoredResponseReturnsBondAndChargesOnlyServiceFee() public {
        open();d.answerDA(DEALER,key(),"anchored bytes",0,new bytes32[](0));
        require(d.stake(DEALER)==200&&d.credit(CHALLENGER)==5&&d.credit(DEALER)==6&&d.burned()==4,"service payout incorrect");
        (bool duplicate,)=address(d).call{value:15}(abi.encodeCall(d.openDA,(CHALLENGER,1,1,1,0,0,0)));require(!duplicate,"served record requested twice");
    }
    function testWrongResponseCannotDischargeObligation() public {
        open();(bool wrong,)=address(d).call(abi.encodeCall(d.answerDA,(DEALER,key(),bytes("different record"),0,new bytes32[](0))));require(!wrong,"unanchored answer accepted");
        vm.warp(block.timestamp+61);d.defaultDA(key());require(d.credit(CHALLENGER)==55,"bad response escaped default");
    }
    function testNonRecipientRequestProvesNoRecordRequiredAndForfeitsBondToDealer() public {
        ctx.required=false;open();require(d.credit(DEALER)==5&&d.credit(CHALLENGER)==10&&d.stake(DEALER)==200&&d.burned()==0,"invalid request penalty incorrect");
    }
    function testUnauthorizedRequestCannotOccupyRecipientObligation() public {
        authGood=false;open();require(d.credit(DEALER)==5&&d.stake(DEALER)==200,"forged recipient slashed dealer");
        authGood=true;open();require(d.stake(DEALER)==100,"invalid claimant blocked recipient");
    }
    function testExpiredRetentionRejectsRequestWithoutDealerSlash() public {
        ctx.expiry=block.timestamp+59;open();require(d.stake(DEALER)==200&&d.credit(DEALER)==5,"expired obligation charged dealer");
    }
    function coefficientFixture(bool bothWrong,bool padded) internal returns(bytes32[] memory sp,bytes32[] memory tp){
        ctx.ts=padded?1:2;bytes32 zero0=leaf(0,0,0);bytes32 zero1=leaf(1,0,0);bytes32 g0=leaf(0,1,2);
        ctx.src=padded?zero0:keccak256(abi.encodePacked(zero0,zero1));
        ctx.tgt=keccak256(abi.encodePacked(g0,bothWrong?leaf(1,1,2):zero1));
        sp=new bytes32[](padded?0:1);if(!padded)sp[0]=zero0;tp=new bytes32[](1);tp[0]=g0;
    }
    function narrow() internal {begin();respond();(,,bytes32[] memory midpoint,)=trace(2);d.move(CHALLENGER,1,2,midpoint);(,,bytes32[] memory dealerMidpoint,)=trace(P-2);d.move(DEALER,1,2,dealerMidpoint);}
    function testFinalComputationUsesAnchoredCoefficientDifference() public {
        (bytes32[] memory sp,bytes32[] memory tp)=coefficientFixture(false,false);narrow();
        d.finishGame(0,0,0,0,sp,tp,1,new bytes32[](0),new bytes32[](0));
        require(d.credit(CHALLENGER)==10&&d.credit(DEALER)==0,"incorrect trace defended record");
    }
    function testBothIncorrectTracesBurnBothDeposits() public {
        (bytes32[] memory sp,bytes32[] memory tp)=coefficientFixture(true,false);narrow();
        d.finishGame(0,0,1,2,sp,tp,1,new bytes32[](0),new bytes32[](0));
        require(d.credit(CHALLENGER)==0&&d.credit(DEALER)==0&&d.burned()==10,"neither true trace must win");
    }
    function testThresholdPaddingRequiresIdentityAndNoOpening() public {
        (bytes32[] memory sp,bytes32[] memory tp)=coefficientFixture(false,true);narrow();bytes32[] memory forged=new bytes32[](1);
        (bool forgedPadding,)=address(d).call(abi.encodeCall(d.finishGame,(0,0,0,0,sp,tp,1,forged,new bytes32[](0))));require(!forgedPadding,"padding supplied fictitious outer opening");
        d.finishGame(0,0,0,0,sp,tp,1,new bytes32[](0),new bytes32[](0));require(d.credit(CHALLENGER)==10,"padded computation failed");
    }
    function testIndependentModuleCannotBeMutatedByExternalAccount() public {
        vm.prank(CHALLENGER);(bool ok,)=address(d).call(abi.encodeCall(d.deposit,(CHALLENGER)));require(!ok,"module caller bypass");
    }
}
