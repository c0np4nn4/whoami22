// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;
import "../contracts/E2EVess.sol";

contract CommitteeScaleHarness is E2EVess {
    function seedCertificateKeys() external {
        committeeN=385;committeeK=129;committeeF=128;
        for(uint256 id=1;id<=385;id++)reservationKeys[id]=base();
    }
    function certificate(bool duplicate) external view returns(uint256[] memory sigs) {
        bytes32 message=keccak256("scale-test");
        Pt memory r=mul(base(),13);
        uint256 c=uint256(keccak256(abi.encodePacked("BN-SIG-v1",uint256(1),uint256(2),r.x,r.y,message)))%Q;
        sigs=new uint256[](257*4);
        for(uint256 i=0;i<257;i++) {
            sigs[4*i]=i==256?(duplicate?256:385):i+1;
            sigs[4*i+1]=r.x;sigs[4*i+2]=r.y;sigs[4*i+3]=addmod(13,c,Q);
        }
    }
    function verify(uint256[] calldata sigs) external view {
        quorum(keccak256("scale-test"),sigs,true);
    }
}

contract CommitteeScaleTest {
    function testLargeConfigurationAndBootstrap() public {
        E2EVess h=new E2EVess();
        h.configureGeneration(49,17,16,120);
        uint256[] memory keys=new uint256[](49*4);
        bytes32[] memory roots=new bytes32[](49);
        for(uint256 id=1;id<=49;id++) {
            h.register(id,0,1,2,address(uint160(id+100)));
            keys[4*(id-1)]=1;keys[4*(id-1)+1]=2;
            keys[4*(id-1)+2]=1;keys[4*(id-1)+3]=2;
        }
        h.bootstrap(keccak256("large-state"),0,8,49,17,16,keys,roots);
        require(h.committeeN()==49&&h.committeeF()==16,"large bootstrap");
    }
    function testSignersAbove255AndDuplicateRejection() public {
        CommitteeScaleHarness h=new CommitteeScaleHarness();
        h.seedCertificateKeys();
        h.verify(h.certificate(false));
        (bool ok,)=address(h).staticcall(abi.encodeCall(h.verify,(h.certificate(true))));
        require(!ok,"duplicate signer 256 accepted");
    }
}
