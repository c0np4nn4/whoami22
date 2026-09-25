// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface RegistryLifecycle {
    function currentState() external view returns(bytes32);
    function stateEpoch(bytes32) external view returns(uint256);
    function stateT(bytes32) external view returns(uint256);
    function committeeN() external view returns(uint256);
    function committeeK() external view returns(uint256);
    function keyEpoch(uint256) external view returns(uint256);
    function dealerKeys(uint256,uint256) external view returns(uint256,uint256);
    function coefficientRoot(bytes32,uint256) external view returns(bytes32);
}

/// A separately deployed module keeps the lifecycle contract below EIP-170.
/// Only its immutable lifecycle controller can invoke a state transition; all
/// attestations are still checked against that controller's canonical state.
contract E2ERegistry {
    uint256 constant Q=21888242871839275222246405745257275088548364400416034343698204186575808495617;
    struct Pt{uint256 x;uint256 y;}
    RegistryLifecycle public immutable lifecycle;
    uint256 public pendingParticipants;
    uint256 public population;
    mapping(uint256=>Pt) public participantKeys;
    mapping(uint256=>bool) public activeParticipant;
    struct Activation {bytes32 alpha;bytes32 state;uint256 status;uint256 deadline;}
    uint256 internal activationSequence;
    mapping(uint256=>Activation) internal activations;
    mapping(bytes32=>uint256) internal participantKeyOwner;
    uint256[] internal participantIdentifiers;
    mapping(bytes32=>uint256[]) internal issuanceCertificates;
    event IssuanceCompleted(uint256 indexed id,bytes32 indexed alpha,bytes32 indexed state,uint256[] certificate);

    constructor(address controller){lifecycle=RegistryLifecycle(controller);}
    modifier onlyLifecycle(){require(msg.sender==address(lifecycle),"lifecycle controller");_;}
    function add(Pt memory a,Pt memory b) internal view returns(Pt memory r){uint256[4] memory input=[a.x,a.y,b.x,b.y];bool ok;assembly("memory-safe"){ok:=staticcall(gas(),6,input,128,r,64)}require(ok,"ecadd");}
    function mul(Pt memory a,uint256 s) internal view returns(Pt memory r){require(s<Q,"scalar");uint256[3] memory input=[a.x,a.y,s];bool ok;assembly("memory-safe"){ok:=staticcall(gas(),7,input,96,r,64)}require(ok,"ecmul");}
    function eq(Pt memory a,Pt memory b) internal pure returns(bool){return a.x==b.x&&a.y==b.y;}
    function base() internal pure returns(Pt memory){return Pt(1,2);}
    function point(uint256[] calldata d,uint256 at) internal pure returns(Pt memory){return Pt(d[at],d[at+1]);}
    function startActivation(uint256 id) internal {
        bytes32 state=lifecycle.currentState();require(state!=0,"no epoch");
        activations[id]=Activation(bytes32(++activationSequence),state,1,block.timestamp+3600);
        pendingParticipants++;
    }
    function activation(uint256 id) external view returns(bytes32,bytes32,uint256,uint256,uint256,uint256) {
        Activation storage a=activations[id];Pt memory pk=participantKeys[id];
        uint256 status=a.status==1&&block.timestamp>a.deadline?3:a.status;
        return(a.alpha,a.state,status,lifecycle.stateEpoch(a.state),pk.x,pk.y);
    }
    function eligibleParticipants() external view returns(uint256[] memory ids){
        ids=new uint256[](population);uint256 count;
        for(uint256 i=0;i<participantIdentifiers.length;i++){
            uint256 id=participantIdentifiers[i];if(activeParticipant[id])ids[count++]=id;
        }
        require(count==population,"registry population invariant");
    }
    function expireActivation(uint256 id) external onlyLifecycle {
        Activation storage a=activations[id];require(a.status==1&&block.timestamp>a.deadline,"activation not expired");
        a.status=3;pendingParticipants--;
    }
    function registerParticipant(uint256 id,bytes32 state,uint256 x,uint256 y,uint256 rx,uint256 ry,uint256 s) external onlyLifecycle {
        require(id>0&&(x!=0||y!=0),"participant registration");mul(Pt(x,y),1);
        Pt memory old=participantKeys[id];bytes32 key=keccak256(abi.encodePacked(x,y));
        require(state==(old.x!=0||old.y!=0?activations[id].state:lifecycle.currentState()),"registration epoch");
        bytes32 message=keccak256(abi.encodePacked("VESS-REGISTER-v1",state,id,x,y));
        uint256 c=uint256(keccak256(abi.encodePacked("BN-SIG-v1",x,y,rx,ry,message)))%Q;
        require((rx!=0||ry!=0)&&eq(mul(base(),s),add(Pt(rx,ry),mul(Pt(x,y),c))),"registration proof of possession");
        require(participantKeyOwner[key]==0||participantKeyOwner[key]==id,"public key already used");
        if(old.x!=0||old.y!=0){require(eq(old,Pt(x,y)),"conflicting identifier reuse");return;}
        participantKeys[id]=Pt(x,y);participantKeyOwner[key]=id;participantIdentifiers.push(id);startActivation(id);
    }
    function issuanceEvaluation(bytes32 state,uint256 dealer,uint256 recipient,uint256[] calldata vectors,uint256 offset) internal view returns(Pt memory value){
        uint256 t=lifecycle.stateT(state);uint256 width=1;while(width<t)width*=2;
        bytes32[] memory layer=new bytes32[](width);uint256 power=1;
        for(uint256 l=0;l<t;l++){
            Pt memory p=point(vectors,offset+2*l);
            layer[l]=keccak256(abi.encodePacked(l,p.x,p.y));
            value=add(value,mul(p,power));power=mulmod(power,recipient,Q);
        }
        while(width>1){for(uint256 l=0;l<width/2;l++)layer[l]=keccak256(abi.encodePacked(layer[2*l],layer[2*l+1]));width/=2;}
        require(layer[0]==lifecycle.coefficientRoot(state,dealer),"issuance vector anchor");
    }
    function activate(uint256 id,bytes32 state,uint256[] calldata attestations,uint256[] calldata vectors) external onlyLifecycle {
        Activation storage a=activations[id];Pt memory pk=participantKeys[id];
        require(a.status==1&&block.timestamp<=a.deadline&&a.state==state&&state==lifecycle.currentState()&&!activeParticipant[id],"activation state");
        uint256 count=attestations.length/7;uint256 n=lifecycle.committeeN();uint256 t=lifecycle.stateT(state);
        require(attestations.length%7==0&&count>=lifecycle.committeeK()&&count<=n&&vectors.length==count*t*2,"issuance certificate size");
        uint256 previous;
        for(uint256 i=0;i<count;i++){
            uint256 at=7*i;uint256 dealer=attestations[at];uint256 epoch=attestations[at+1];
            require(dealer>previous&&dealer<=n&&epoch==lifecycle.keyEpoch(dealer),"issuance signer");previous=dealer;
            Pt memory evaluation=issuanceEvaluation(state,dealer,id,vectors,i*t*2);
            require(eq(evaluation,point(attestations,at+2)),"issuance evaluation");
            bytes32 message=keccak256(abi.encodePacked("VESS-ISSUANCE-v1",a.alpha,state,lifecycle.stateEpoch(state),id,pk.x,pk.y,dealer,epoch,evaluation.x,evaluation.y));
            Pt memory signer;(signer.x,signer.y)=lifecycle.dealerKeys(dealer,epoch);require(signer.x!=0||signer.y!=0,"issuance key");
            Pt memory r=point(attestations,at+4);require(r.x!=0||r.y!=0,"issuance nonce point");
            uint256 c=uint256(keccak256(abi.encodePacked("BN-SIG-v1",signer.x,signer.y,r.x,r.y,message)))%Q;
            require(eq(mul(base(),attestations[at+6]),add(r,mul(signer,c))),"issuance signature");
        }
        issuanceCertificates[a.alpha]=attestations;a.status=2;activeParticipant[id]=true;pendingParticipants--;population++;
        emit IssuanceCompleted(id,a.alpha,state,attestations);
    }
    function beginRecovery(uint256 id) external onlyLifecycle {require(activeParticipant[id],"recovery authorization");activeParticipant[id]=false;population--;startActivation(id);}
}
