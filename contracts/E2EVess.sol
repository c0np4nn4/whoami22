// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;
import "./E2EGeneration.sol";
import "./E2ERegistry.sol";
import "./E2EDisputes.sol";
import "./E2EPublication.sol";

/// BN254 lifecycle integration verifier and Anvil-ordered state machine.
contract E2EVess {
    error ProtocolCheck();
    uint256 constant P=21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant Q=21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant BLS=52435875175126190479447740508185965837690552500527637822603658699938581184513;
    struct Pt{uint256 x;uint256 y;}
    Pt internal H;
    address public immutable admin;
    E2EGeneration public immutable generationBoard;
    E2ERegistry public immutable registry;
    E2EDisputes public immutable disputes;
    E2EPublication public publicationStore;
    function setPublicationStore(E2EPublication store) external {require(msg.sender==admin&&address(publicationStore)==address(0)&&store.host()==address(this),ProtocolCheck());publicationStore=store;}
    mapping(uint256=>mapping(uint256=>Pt)) public dealerKeys;
    mapping(uint256=>uint256) public keyEpoch;mapping(uint256=>address) public dealerAccount;
    event Anchor(bytes32 root,bytes32 versioned);
    constructor(){admin=msg.sender;generationBoard=new E2EGeneration(address(this));registry=new E2ERegistry(address(this));disputes=new E2EDisputes(address(this));H=Pt(17921123236960707427710825259516267029141452100634855407537533008926937422493,13328568728238200693103914680868918147255281106638416828545947743298325819348);}
    function add(Pt memory a,Pt memory b) internal view returns(Pt memory r){uint256[4] memory input=[a.x,a.y,b.x,b.y];bool ok;assembly("memory-safe"){ok:=staticcall(gas(),6,input,128,r,64)}require(ok, ProtocolCheck() /* ecadd */);}
    function mul(Pt memory a,uint256 s) internal view returns(Pt memory r){require(s<Q, ProtocolCheck() /* scalar */);uint256[3] memory input=[a.x,a.y,s];bool ok;assembly("memory-safe"){ok:=staticcall(gas(),7,input,96,r,64)}require(ok, ProtocolCheck() /* ecmul */);}
    function neg(Pt memory a) internal pure returns(Pt memory){return Pt(a.x,a.y==0?0:P-a.y);}
    function eq(Pt memory a,Pt memory b) internal pure returns(bool){return a.x==b.x&&a.y==b.y;}
    function base() internal pure returns(Pt memory){return Pt(1,2);}
    // The existing publication verifier also hosts the deterministic record
    // hash-to-curve helper, keeping this constructor within EIP-3860.
    function hashPoint(bytes32 seed) internal view returns(Pt memory p){(p.x,p.y)=publicationStore.hashPoint(seed);}
    function point(uint256[] calldata d,uint256 at) internal pure returns(Pt memory){return Pt(d[at],d[at+1]);}
    function register(uint256 id,uint256 epoch,uint256 x,uint256 y,address account) external {require(msg.sender==admin, ProtocolCheck() /* admin */);require(epoch>=keyEpoch[id], ProtocolCheck() /* retired */);Pt memory old=dealerKeys[id][epoch];require((old.x==0&&old.y==0)||(old.x==x&&old.y==y), ProtocolCheck() /* immutable historical key */);require(x!=0||y!=0, ProtocolCheck() /* identity key */);require(account!=address(0), ProtocolCheck() /* dealer account */);dealerKeys[id][epoch]=Pt(x,y);keyEpoch[id]=epoch;dealerAccount[id]=account;}

    // Public ABI forwards to the separately deployed immutable bulletin board.
    function generationRoundSeconds() external view returns(uint256){return generationBoard.roundSeconds();}
    function generationOwner() external view returns(address){return generationBoard.owner();}
    function generationOpened(uint256 nonce) external view returns(bool){return generationBoard.opened(nonce);}
    function initialConstant() external view returns(bytes memory){return generationBoard.initialConstant();}
    function configureGeneration(uint256 n,uint256 k,uint256 f,uint256 roundSeconds) external {
        require(msg.sender==admin&&currentState==0&&k>f&&n>=2*f+k, ProtocolCheck() /* generation parameters */);
        committeeN=n;committeeK=k;committeeF=f;generationBoard.configure(roundSeconds);
    }
    function publishGeneration(uint256 nonce,uint256 phase,uint256 id,bytes calldata payload) external {generationBoard.publish(msg.sender,nonce,phase,id,payload);}
    function openGeneration(uint256 nonce) external {require(msg.sender==admin, ProtocolCheck() /* admin */);generationBoard.open(nonce);}
    function setGenerationOwner(address owner) external {require(msg.sender==admin, ProtocolCheck() /* admin */);generationBoard.setOwner(owner);}
    function publishInitialConstant(bytes calldata payload) external {generationBoard.publishInitial(msg.sender,payload);}
    function closeGeneration(uint256 nonce,uint256 phase) external {generationBoard.close(nonce,phase);}
    function generationPhase(uint256 nonce,uint256 phase) external view returns(uint256,uint256,bool){return generationBoard.phase(nonce,phase);}
    function generationMessage(uint256 nonce,uint256 phase,uint256 id) external view returns(bytes memory){return generationBoard.message(nonce,phase,id);}

    function rootOpeningFor(bytes32 expectedRoot,bytes32 expectedVersion,bytes calldata p0,bytes calldata p1) internal view {require(p1.length==0,ProtocolCheck());publicationStore.verifyRoot(expectedRoot,expectedVersion,p0);}
    function member(bytes32 r,bytes32 leaf,uint256 index,bytes32[] calldata path) public view returns(bool){return publicationStore.member(r,leaf,index,path);}
    function adHash(uint256[] calldata r) internal pure returns(bytes32){require(r.length==25, ProtocolCheck() /* record length */);return keccak256(abi.encodePacked(r[:14]));}
    function recordHash(uint256[] calldata r) internal pure returns(bytes32){return keccak256(abi.encodePacked(r));}
    function signature(uint256[] calldata r) internal view returns(bool){Pt memory pk=dealerKeys[r[0]][r[4]];require(pk.x!=0||pk.y!=0, ProtocolCheck() /* registered key */);uint256 c=uint256(keccak256(abi.encodePacked("BN-SIG-v1",pk.x,pk.y,r[22],r[23],keccak256(abi.encodePacked(r[:22])))))%Q;return eq(mul(base(),r[24]),add(point(r,22),mul(pk,c)));}
    function dleq(Pt memory b2,Pt memory p1,Pt memory p2,bytes32 context,uint256 c,uint256 s) internal view returns(bool){require(c<Q&&s<Q, ProtocolCheck() /* proof scalar */);require(p1.x!=0||p1.y!=0, ProtocolCheck() /* identity public */);require(p2.x!=0||p2.y!=0, ProtocolCheck() /* identity shared */);Pt memory a=add(mul(base(),s),neg(mul(p1,c)));Pt memory b=add(mul(b2,s),neg(mul(p2,c)));return c==uint256(keccak256(abi.encodePacked("BN-DLEQ-v1",context,b2.x,b2.y,p1.x,p1.y,p2.x,p2.y,a.x,a.y,b.x,b.y)))%Q;}
    function pop(uint256[] calldata r) public view returns(bool){bytes32 ad=adHash(r);Pt memory hp=hashPoint(keccak256(abi.encodePacked("epk-pop",ad,r[14],r[15])));return dleq(hp,point(r,14),point(r,16),ad,r[18],r[19]);}
    function authenticated(uint256[] calldata r,uint256 index,bytes32[] calldata path) internal view returns(bytes32 id){
        require(r.length==25&&r[0]>0&&r[0]<=committeeN&&r[1]>0&&r[3]==0&&r[20]<Q&&r[21]<Q, ProtocolCheck());
        Attempt storage a=attempts[r[2]];require(a.status==3,ProtocolCheck());
        require(r[7]==uint256(coefficientRoots[a.source][r[0]-1])&&r[8]==uint256(coefficientRoots[a.target][r[0]-1]), ProtocolCheck());
        require(r[4]==a.keys[r[0]-1]&&r[5]==stateEpoch[a.source]&&r[6]==stateEpoch[a.target],ProtocolCheck());
        require(eq(point(r,12),participantKeys(r[1])),ProtocolCheck());id=recordHash(r);
        require(recordMember(a.root,fieldHash(abi.encodePacked("VESS-RECORD-v1",index,id)),index,path)&&signature(r),ProtocolCheck());
    }
    function verifyRecord(uint256[] calldata r,uint256 index,bytes32[] calldata path,bytes calldata p0,bytes calldata p1) external view returns(bytes32 id){
        require(r.length==25,ProtocolCheck());Attempt storage a=attempts[r[2]];rootOpeningFor(a.root,a.versioned,p0,p1);return authenticated(r,index,path);
    }
    function verifyPlaintext(uint256[] calldata r,uint256[] calldata dp) external view returns(bool proofGood,bool plaintextGood){
        if(dp.length!=4)return(false,false);
        bytes32 context=keccak256(abi.encodePacked("DEC",adHash(r),r[14],r[15],r[20],r[21]));
        if(!dleq(point(r,14),point(r,12),point(dp,0),context,dp[2],dp[3]))return(false,false);
        uint256 kv=uint256(keccak256(abi.encodePacked("derive-key-0",adHash(r),r[1],r[12],r[13],r[14],r[15],dp[0],dp[1])))%Q;
        uint256 kr=uint256(keccak256(abi.encodePacked("derive-key-1",adHash(r),r[1],r[12],r[13],r[14],r[15],dp[0],dp[1])))%Q;
        return(true,eq(add(mul(base(),addmod(r[20],Q-kv,Q)),mul(H,addmod(r[21],Q-kr,Q))),point(r,10)));
    }
    function fieldHash(bytes memory data) internal pure returns(bytes32){return bytes32(uint256(keccak256(data))&((uint256(1)<<248)-1));}
    function recordMember(bytes32 r,bytes32 leaf,uint256 index,bytes32[] calldata path) public view returns(bool){return publicationStore.recordMember(r,leaf,index,path);}
    function disputeContext(uint256 nonce,uint256 dealer,uint256 recipient) external view returns(DisputeContext memory c){
        Attempt storage a=attempts[nonce];require(a.status==3&&dealer>0&&dealer<=committeeN,ProtocolCheck());
        c.anchor=a.root;c.src=coefficientRoots[a.source][dealer-1];c.tgt=coefficientRoots[a.target][dealer-1];c.source=a.source;c.target=a.target;
        c.ts=stateT[a.source];c.tt=a.t;c.n=committeeN;c.account=a.accounts[dealer-1];c.expiry=a.finalizedAt+disputes.retentionSeconds();
        for(uint256 i=0;i<a.offline.length;i++)if(a.offline[i]==recipient)c.required=true;
    }
    function verifyDA(address caller,uint256 nonce,uint256 dealer,uint256 recipient,uint256 rx,uint256 ry,uint256 s) external view returns(bool){
        Pt memory pk=participantKeys(recipient);if(pk.x==0&&pk.y==0)return false;
        bytes32 message=keccak256(abi.encodePacked("VESS-DA-v1",block.chainid,address(this),nonce,dealer,recipient,caller));
        uint256 c=uint256(keccak256(abi.encodePacked("BN-SIG-v1",pk.x,pk.y,rx,ry,message)))%Q;
        return eq(mul(base(),s),add(Pt(rx,ry),mul(pk,c)));
    }
    function verifyDAResponse(uint256 nonce,uint256 dealer,uint256 recipient,bytes calldata raw,uint256 index,bytes32[] calldata path) external view returns(bool){
        require(raw.length==800,ProtocolCheck());uint256[] memory r=new uint256[](25);for(uint256 i=0;i<25;i++){uint256 v;assembly("memory-safe"){v:=calldataload(add(raw.offset,mul(i,32)))}r[i]=v;}
        require(r[0]==dealer&&r[1]==recipient&&r[2]==nonce,ProtocolCheck());return this.verifyAnchoredRecord(r,index,path)==keccak256(raw);
    }
    function verifyAnchoredRecord(uint256[] calldata r,uint256 index,bytes32[] calldata path) external view returns(bytes32){return authenticated(r,index,path);}
    function admitRecord(uint256[] calldata r,uint256 index,bytes32[] calldata path,bytes calldata p0,bytes calldata p1) external returns(bytes32){return disputes.admitRecord(r,index,path,p0,p1);}
    function plaintext(uint256[] calldata r,uint256[] calldata dp,uint256 index,bytes32[] calldata path,bytes calldata p0,bytes calldata p1) external payable returns(bool){return disputes.plaintext{value:msg.value}(msg.sender,r,dp,index,path,p0,p1);}
    event Verdict(bytes32 indexed record,uint256 kind,bool value);
    function beginGame(bytes32 id,bytes32 rc,uint256 cx,uint256 cy,bytes32[] calldata c0,bytes32[] calldata ct) external {disputes.beginGame(msg.sender,id,rc,cx,cy,c0,ct);}
    function respondGame(bytes32 rd,bytes32[] calldata d0,bytes32[] calldata dt) external {disputes.respondGame(msg.sender,rd,d0,dt);}
    function move(uint256 x,uint256 y,bytes32[] calldata proof) external {disputes.move(msg.sender,x,y,proof);}
    function finishGame(uint256 sx,uint256 sy,uint256 tx_,uint256 ty,bytes32[] calldata sp,bytes32[] calldata tp,uint256 recordCount,bytes32[] calldata sourcePath,bytes32[] calldata targetPath) external {disputes.finishGame(sx,sy,tx_,ty,sp,tp,recordCount,sourcePath,targetPath);}
    function gameTimeout() external {disputes.gameTimeout();}
    function openDA(uint256 nonce,uint256 dealer,uint256 recipient,uint256 rx,uint256 ry,uint256 s) external payable {disputes.openDA{value:msg.value}(msg.sender,nonce,dealer,recipient,rx,ry,s);}
    function answerDA(bytes32 key,bytes calldata raw,uint256 index,bytes32[] calldata path) external {disputes.answerDA(msg.sender,key,raw,index,path);}
    function defaultDA(bytes32 key) external {disputes.defaultDA(key);}
    function deposit() external payable {disputes.deposit{value:msg.value}(msg.sender);}
    function withdraw() external {disputes.withdraw(msg.sender);}
    function stake(address who) external view returns(uint256){return disputes.stake(who);}
    function credit(address who) external view returns(uint256){return disputes.credit(who);}
    function burned() external view returns(uint256){return disputes.burned();}
    function finderPaid() external view returns(uint256){return disputes.finderPaid();}
    function servicePaid() external view returns(uint256){return disputes.servicePaid();}
    function bondsReturned() external view returns(uint256){return disputes.bondsReturned();}
    function forfeited() external view returns(uint256){return disputes.forfeited();}
    function admitted(bytes32 id) external view returns(bool){return disputes.admitted(id);}
    function configureDisputes(uint256 round,uint256 response,uint256 retention) external {require(msg.sender==admin&&currentState==0,ProtocolCheck());disputes.configure(round,response,retention);}

    uint256 public committeeN; uint256 public committeeK; uint256 public committeeF;
    uint256 public participantCorruptionBudget=1;
    uint256 public outgoingRecipientBudget=2;
    // Fixed for the lifecycle before the initial state can receive a share.
    function configureReleasePolicy(uint256 corruption,uint256 outgoing) external {
        require(msg.sender==admin&&currentState==0,ProtocolCheck());
        participantCorruptionBudget=corruption;outgoingRecipientBudget=outgoing;
    }
    bytes32 public currentState;
    mapping(uint256=>Pt) public reservationKeys;
    mapping(bytes32=>bool) public committed; mapping(bytes32=>uint256) public stateT;
    mapping(bytes32=>uint256) public stateEpoch; mapping(bytes32=>bytes32[]) internal coefficientRoots;
    mapping(bytes32=>bytes32) public releaseRoot; mapping(bytes32=>mapping(uint256=>bool)) internal charged;
    mapping(bytes32=>mapping(uint256=>bool)) internal incomingOffline;
    mapping(bytes32=>uint256) internal chargedCount; mapping(bytes32=>uint256) internal unionCount;
    struct Attempt {bytes32 source;bytes32 target;bytes32 reservation;bytes32 root;bytes32 metadata;bytes32 versioned;uint256 t;uint256 status;uint256[] offline;uint256[] keys;address[] accounts;uint256 finalizedAt;}
    mapping(uint256=>Attempt) internal attempts;
    event EpochCommit(uint256 indexed nonce,bytes32 indexed source,bytes32 indexed target,bytes32 root,bytes32 metadata);
    event ReleaseReservation(uint256 indexed nonce,bytes32 digest,bytes32 nextRoot);
    function quorum(bytes32 message,uint256[] calldata sigs,bool reservationKey) internal view {
        require(sigs.length%4==0&&sigs.length/4>=committeeN-committeeF, ProtocolCheck() /* quorum */); bytes memory seen=new bytes(committeeN);
        for(uint256 i=0;i<sigs.length;i+=4){uint256 id=sigs[i];require(id>0&&id<=committeeN, ProtocolCheck() /* signer */);
            // One byte per dealer: no 256-bit identity ceiling. Bounds above
            // ensure this byte lies within the allocated memory buffer.
            uint256 duplicate;
            assembly("memory-safe") {let index:=sub(id,1) let data:=add(seen,32) duplicate:=byte(and(index,31),mload(add(data,and(index,not(31))))) mstore8(add(data,index),1)}
            require(duplicate==0, ProtocolCheck() /* duplicate signer */);
            Pt memory pk=reservationKey?reservationKeys[id]:dealerKeys[id][keyEpoch[id]];
            uint256 c=uint256(keccak256(abi.encodePacked("BN-SIG-v1",pk.x,pk.y,sigs[i+1],sigs[i+2],message)))%Q;
            require(eq(mul(base(),sigs[i+3]),add(Pt(sigs[i+1],sigs[i+2]),mul(pk,c))), ProtocolCheck() /* certificate signature */);}
    }
    function bootstrap(bytes32 state,uint256 epoch,uint256 t,uint256 n,uint256 k,uint256 f,uint256[] calldata keys,bytes32[] calldata roots) external {
        require(msg.sender==admin&&currentState==0&&participantCorruptionBudget<t&&k>f&&n>=2*f+k&&keys.length==4*n&&roots.length==n, ProtocolCheck() /* bootstrap */);
        committeeN=n;committeeK=k;committeeF=f;currentState=state;committed[state]=true;stateT[state]=t;stateEpoch[state]=epoch;coefficientRoots[state]=roots;
        for(uint256 i=0;i<n;i++){require(dealerAccount[i+1]!=address(0), ProtocolCheck() /* dealer setup */);require(eq(dealerKeys[i+1][0],Pt(keys[4*i],keys[4*i+1])), ProtocolCheck() /* initial dealer key */);reservationKeys[i+1]=Pt(keys[4*i+2],keys[4*i+3]);}
    }
    // Public ABI remains on the lifecycle contract; cryptographic registry
    // state lives in a separately deployed, immutable controller-only module.
    function participantKeys(uint256 id) public view returns(Pt memory p){(p.x,p.y)=registry.participantKeys(id);}
    function activeParticipant(uint256 id) public view returns(bool){return registry.activeParticipant(id);}
    function pendingParticipants() public view returns(uint256){return registry.pendingParticipants();}
    function population() public view returns(uint256){return registry.population();}
    function activation(uint256 id) external view returns(bytes32,bytes32,uint256,uint256,uint256,uint256){return registry.activation(id);}
    function eligibleParticipants() external view returns(uint256[] memory){return registry.eligibleParticipants();}
    function expireActivation(uint256 id) external {registry.expireActivation(id);}
    function registerParticipant(uint256 id,bytes32 state,uint256 x,uint256 y,uint256 rx,uint256 ry,uint256 s) external {
        require(msg.sender==admin, ProtocolCheck() /* participant registration admin */);registry.registerParticipant(id,state,x,y,rx,ry,s);
    }
    function activate(uint256 id,bytes32 state,uint256[] calldata attestations,uint256[] calldata vectors) external {registry.activate(id,state,attestations,vectors);}
    function coefficientRoot(bytes32 state,uint256 dealer) external view returns(bytes32){require(dealer>0&&dealer<=committeeN, ProtocolCheck() /* dealer root */);return coefficientRoots[state][dealer-1];}
    function reserve(bytes32 source,bytes32 target,uint256 nonce,uint256 targetT,uint256 eligible,bytes32 oldRoot,uint256[] calldata off,uint256[] calldata sigs) external {
        Attempt storage previous=attempts[nonce];
        require(source==currentState&&(previous.status==0||previous.status==1)&&nonce>0&&pendingParticipants()==0, ProtocolCheck() /* reserve state */);
        if(previous.status==1){
            require(previous.versioned==0,ProtocolCheck() /* publication already started */);
            require(previous.source==source&&previous.target==target&&previous.t==targetT&&off.length>previous.offline.length, ProtocolCheck() /* reservation extension */);
            for(uint256 a=0;a<previous.offline.length;a++){bool retained;for(uint256 b=0;b<off.length;b++){if(previous.offline[a]==off[b])retained=true;}require(retained, ProtocolCheck() /* cannot unreserve recipient */);}
        }
        require(participantCorruptionBudget+off.length+outgoingRecipientBudget<targetT&&eligible>=targetT&&eligible==population()&&oldRoot==releaseRoot[source], ProtocolCheck() /* budget/CAS */);
        bytes32 nextRoot=keccak256(abi.encodePacked(oldRoot,keccak256(abi.encodePacked(off)),nonce,target));
        bytes32 message=keccak256(abi.encodePacked("RESERVE",source,target,nonce,targetT,eligible,oldRoot,nextRoot,keccak256(abi.encodePacked(off))));quorum(message,sigs,true);
        for(uint256 i=0;i<off.length;i++){require(activeParticipant(off[i]), ProtocolCheck() /* offline registration */);for(uint256 j=0;j<i;j++)require(off[j]!=off[i], ProtocolCheck() /* duplicate offline */);if(!charged[source][off[i]]){charged[source][off[i]]=true;chargedCount[source]++;if(!incomingOffline[source][off[i]])unionCount[source]++;}}
        require(chargedCount[source]<=outgoingRecipientBudget&&participantCorruptionBudget+unionCount[source]<stateT[source], ProtocolCheck() /* source exposure */);
        releaseRoot[source]=nextRoot;Attempt storage a=attempts[nonce];a.source=source;a.target=target;a.t=targetT;a.reservation=message;a.offline=off;a.status=1;emit ReleaseReservation(nonce,message,nextRoot);
    }
    function reservation(uint256 nonce) external view returns(bytes32){return attempts[nonce].reservation;}
    function publish(uint256 nonce,bytes32 recordRoot,bytes32 metadata,bytes32[] calldata roots,uint256 length,uint256 offset,bytes calldata proofs) external {
        require(msg.sender==admin,ProtocolCheck());Attempt storage a=attempts[nonce];require(a.status==1&&roots.length==committeeN,ProtocolCheck());
        bytes32 version=publicationStore.append(nonce,recordRoot,metadata,length,offset,proofs);
        if(version==0){a.versioned=blobhash(0);return;}
        a.root=recordRoot;a.metadata=metadata;a.versioned=version;coefficientRoots[a.target]=roots;stateT[a.target]=a.t;stateEpoch[a.target]=stateEpoch[a.source]+1;
        for(uint256 i=1;i<=committeeN;i++){a.keys.push(keyEpoch[i]);a.accounts.push(dealerAccount[i]);}a.status=2;emit Anchor(recordRoot,a.versioned);
    }
    function commitEpoch(uint256 nonce,uint256[] calldata sigs) external {
        Attempt storage a=attempts[nonce];require(a.status==2&&a.source==currentState&&pendingParticipants()==0, ProtocolCheck() /* commit state */);bytes32 message=keccak256(abi.encodePacked("COMMIT",a.source,a.target,nonce,a.root,a.metadata));quorum(message,sigs,false);
        a.status=3;a.finalizedAt=block.timestamp;committed[a.target]=true;currentState=a.target;
        for(uint256 i=0;i<a.offline.length;i++){incomingOffline[a.target][a.offline[i]]=true;unionCount[a.target]++;}
        emit EpochCommit(nonce,a.source,a.target,a.root,a.metadata);
    }
    function abortEpoch(uint256 nonce) external {require(msg.sender==admin&&attempts[nonce].status>0&&attempts[nonce].status<3, ProtocolCheck() /* abort */);attempts[nonce].status=4;}
    function publication(uint256 nonce) external view returns(bytes32,bytes32,bytes32,bytes32,bytes32,uint256){Attempt storage a=attempts[nonce];return(a.root,a.metadata,a.versioned,a.source,a.target,a.status);}
    function publicationKeyEpoch(uint256 nonce,uint256 dealer) external view returns(uint256){Attempt storage a=attempts[nonce];require(a.status>=2&&dealer>0&&dealer<=committeeN&&a.keys.length==committeeN, ProtocolCheck() /* published signer snapshot */);return a.keys[dealer-1];}
    function coefficientRootDigest(bytes32 state) external view returns(bytes32){return keccak256(abi.encodePacked(coefficientRoots[state]));}
    function rotate(uint256 id,uint256 epoch,uint256 x,uint256 y,uint256 rx,uint256 ry) external {require(msg.sender==admin&&id>0&&id<=committeeN&&epoch==keyEpoch[id]+1, ProtocolCheck() /* rotation */);dealerKeys[id][epoch]=Pt(x,y);reservationKeys[id]=Pt(rx,ry);keyEpoch[id]=epoch;}
    function beginRecovery(uint256 id) external {require(msg.sender==admin, ProtocolCheck() /* recovery authorization */);registry.beginRecovery(id);}
}
