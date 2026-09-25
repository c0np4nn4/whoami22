// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;
import "../contracts/E2EVess.sol";

interface GenerationVm {function warp(uint256) external;function prank(address) external;}

contract GenerationTest {
    GenerationVm constant vm=GenerationVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    E2EVess board;
    function setUp() public {
        board=new E2EVess();board.configureGeneration(4,2,1,10);
        for(uint256 id=1;id<=4;id++)board.register(id,0,1,2,address(uint160(id+100)));
        board.openGeneration(0);
        board.setGenerationOwner(address(this));board.publishInitialConstant(hex"1234");
    }
    function publish(uint256 phase,uint256 id,bytes memory payload) internal {
        vm.prank(address(uint160(id+100)));board.publishGeneration(0,phase,id,payload);
    }
    function tryPublish(uint256 nonce,uint256 phase,uint256 id,bytes memory payload) internal returns(bool ok){
        vm.prank(address(uint160(id+100)));
        (ok,)=address(board).call(abi.encodeCall(board.publishGeneration,(nonce,phase,id,payload)));
    }
    function testImmutableAuthenticatedAndOrderedTranscript() public {
        require(!tryPublish(1,0,1,hex"01"),"unopened nonce");
        require(!tryPublish(0,1,1,hex"01"),"phase advanced before freeze");
        publish(0,1,hex"01");publish(0,1,hex"01");
        require(!tryPublish(0,0,1,hex"02"),"equivocation accepted");
        (bool ok,)=address(board).call(abi.encodeCall(board.publishGeneration,(0,0,2,hex"01")));
        require(!ok,"wrong sender accepted");
        for(uint256 id=2;id<=4;id++)publish(0,id,abi.encode(id));
        (uint256 count,,bool closed)=board.generationPhase(0,0);require(count==4&&closed,"all-dealer freeze");
        require(keccak256(board.generationMessage(0,0,1))==keccak256(hex"01"),"transcript changed");
        publish(1,1,hex"aa");
    }
    function testOneOmissionClosesAtBoundAndLateMessagesCannotChangeSet() public {
        for(uint256 id=1;id<=3;id++)publish(0,id,abi.encode(id));
        (bool ok,)=address(board).call(abi.encodeCall(board.closeGeneration,(0,0)));require(!ok,"early close");
        vm.warp(block.timestamp+11);board.closeGeneration(0,0);
        (uint256 count,,bool closed)=board.generationPhase(0,0);require(count==3&&closed,"quorum freeze");
        require(board.generationMessage(0,0,4).length==0,"invented missing broadcast");
        require(!tryPublish(0,0,4,hex"01"),"late broadcast changed qualified transcript");
    }
    function testSubquorumCannotFreeze() public {
        publish(0,1,hex"01");publish(0,2,hex"02");vm.warp(block.timestamp+11);
        (bool ok,)=address(board).call(abi.encodeCall(board.closeGeneration,(0,0)));require(!ok,"subquorum freeze");
    }
    function testOwnerConstantIsCanonicalAndImmutable() public {
        require(keccak256(board.initialConstant())==keccak256(hex"1234"),"constant transcript");
        (bool ok,)=address(board).call(abi.encodeCall(board.publishInitialConstant,(hex"5678")));
        require(!ok,"owner constant equivocation");
        E2EVess other=new E2EVess();other.configureGeneration(4,2,1,10);other.setGenerationOwner(address(8));other.openGeneration(0);
        (ok,)=address(other).call(abi.encodeCall(other.publishInitialConstant,(hex"1234")));
        require(!ok,"unauthorized owner broadcast");
    }
    function testChildCannotBeCalledDirectlyToForgeForwardedIdentity() public {
        E2EGeneration child=board.generationBoard();
        (bool ok,)=address(child).call(abi.encodeCall(child.publish,(address(101),0,0,1,hex"01")));
        require(!ok,"forged forwarded dealer");
        (ok,)=address(child).call(abi.encodeCall(child.publishInitial,(address(this),hex"5678")));
        require(!ok,"forged forwarded owner");
    }
}
