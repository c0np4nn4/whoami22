// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

struct DisputeContext {
    bytes32 anchor; bytes32 src; bytes32 tgt; bytes32 source; bytes32 target;
    uint256 ts; uint256 tt; uint256 n; address account; uint256 expiry; bool required;
}
interface DisputeLifecycle {
    function dealerAccount(uint256) external view returns(address);
    function verifyRecord(uint256[] calldata,uint256,bytes32[] calldata,bytes calldata,bytes calldata) external view returns(bytes32);
    function pop(uint256[] calldata) external view returns(bool);
    function verifyPlaintext(uint256[] calldata,uint256[] calldata) external view returns(bool,bool);
    function disputeContext(uint256,uint256,uint256) external view returns(DisputeContext memory);
    function verifyDA(address,uint256,uint256,uint256,uint256,uint256,uint256) external view returns(bool);
    function verifyDAResponse(uint256,uint256,uint256,bytes calldata,uint256,bytes32[] calldata) external view returns(bool);
    function member(bytes32,bytes32,uint256,bytes32[] calldata) external view returns(bool);
    function recordMember(bytes32,bytes32,uint256,bytes32[] calldata) external view returns(bool);
}

/// Implements main.tex's two-stage adjudication and publication obligations.
/// The caller identity is forwarded only by the immutable lifecycle contract.
contract E2EDisputes {
    error InvalidState();
    uint256 constant P=21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant Q=21888242871839275222246405745257275088548364400416034343698204186575808495617;
    struct Pt {uint256 x;uint256 y;}
    DisputeLifecycle public immutable lifecycle;
    uint256 public roundSeconds=60;
    uint256 public responseSeconds=60;
    uint256 public retentionSeconds=3600;
    mapping(address=>uint256) public stake;
    mapping(address=>uint256) public credit;
    uint256 public burned;uint256 public finderPaid;uint256 public servicePaid;uint256 public bondsReturned;uint256 public forfeited;
    struct Record {uint256 nonce;uint256 dealer;uint256 recipient;Pt evaluation;}
    mapping(bytes32=>bool) public admitted;
    mapping(bytes32=>Record) internal records;
    mapping(bytes32=>bool) public plaintextSettled;
    mapping(bytes32=>bool) public consistencySettled;
    event Verdict(bytes32 indexed record,uint256 kind,bool value);
    event DABytes(bytes32 indexed key,bytes raw);
    event GameOpened(bytes32 indexed record,address challenger,address dealer,uint256 deadline);
    event DealerTrace(bytes32 indexed record,bytes32 root,uint256 deadline);
    event DAOpened(bytes32 indexed key,uint256 indexed nonce,uint256 dealer,uint256 recipient,uint256 deadline);
    constructor(address controller){lifecycle=DisputeLifecycle(controller);}
    modifier onlyLifecycle(){require(msg.sender==address(lifecycle),InvalidState());_;}
    function configure(uint256 round,uint256 response,uint256 retention) external onlyLifecycle {require(round>0&&response>0&&retention>response,InvalidState());roundSeconds=round;responseSeconds=response;retentionSeconds=retention;}
    function deposit(address who) external payable onlyLifecycle {stake[who]+=msg.value;}
    function withdraw(address who) external onlyLifecycle {uint256 value=credit[who];credit[who]=0;(bool ok,)=who.call{value:value}("");require(ok,InvalidState());}
    function remember(bytes32 id,uint256[] calldata r) internal {if(!admitted[id]){admitted[id]=true;records[id]=Record(r[2],r[0],r[1],Pt(r[10],r[11]));emit Verdict(id,0,true);}}
    function admitRecord(uint256[] calldata r,uint256 index,bytes32[] calldata path,bytes calldata p0,bytes calldata p1) external onlyLifecycle returns(bytes32 id){
        id=lifecycle.verifyRecord(r,index,path,p0,p1);require(!admitted[id],InvalidState());remember(id,r);
    }
    function claimantLoss(address caller,address dealer,bytes32 id,uint256 kind) internal {if(dealer==address(0))burned+=5;else credit[dealer]+=5;forfeited+=5;emit Verdict(id,kind,false);caller;}
    function plaintext(address caller,uint256[] calldata r,uint256[] calldata dp,uint256 index,bytes32[] calldata path,bytes calldata p0,bytes calldata p1) external payable onlyLifecycle returns(bool){
        require(msg.value==5,InvalidState());bytes32 id;address dealer=r.length>0?lifecycle.dealerAccount(r[0]):address(0);
        try lifecycle.verifyRecord(r,index,path,p0,p1) returns(bytes32 verified){id=verified;}
        catch {claimantLoss(caller,dealer,keccak256(abi.encodePacked(r)),10);return false;}
        require(!plaintextSettled[id],InvalidState());remember(id,r);
        DisputeContext memory context=lifecycle.disputeContext(r[2],r[0],r[1]);dealer=context.account;
        bool possession;try lifecycle.pop(r) returns(bool good){possession=good;}catch{}
        if(!possession){settleMalformed(caller,dealer,id);emit Verdict(id,1,false);return false;}
        bool proofGood;bool plainGood;
        try lifecycle.verifyPlaintext(r,dp) returns(bool p,bool good){proofGood=p;plainGood=good;}catch{}
        if(!proofGood){claimantLoss(caller,dealer,id,11);return false;}
        plaintextSettled[id]=true;
        if(plainGood){claimantLoss(caller,dealer,id,2);}else{settleMalformed(caller,dealer,id);emit Verdict(id,2,false);}
        return plainGood;
    }
    function settleMalformed(address caller,address dealer,bytes32 id) internal {
        require(stake[dealer]>=10,InvalidState());plaintextSettled[id]=true;stake[dealer]-=10;credit[caller]+=9;finderPaid+=4;burned+=6;bondsReturned+=5;
    }
    function add(Pt memory a,Pt memory b) internal view returns(Pt memory r){uint256[4] memory input=[a.x,a.y,b.x,b.y];bool ok;assembly("memory-safe"){ok:=staticcall(gas(),6,input,128,r,64)}require(ok,InvalidState());}
    function mul(Pt memory a,uint256 s) internal view returns(Pt memory r){uint256[3] memory input=[a.x,a.y,s];bool ok;assembly("memory-safe"){ok:=staticcall(gas(),7,input,96,r,64)}require(ok,InvalidState());}
    function neg(Pt memory a) internal pure returns(Pt memory){return Pt(a.x,a.y==0?0:P-a.y);}
    function eq(Pt memory a,Pt memory b) internal pure returns(bool){return a.x==b.x&&a.y==b.y;}
    function pow(uint256 a,uint256 e) internal pure returns(uint256 r){r=1;while(e>0){if(e%2==1)r=mulmod(r,a,Q);a=mulmod(a,a,Q);e/=2;}}
    function fieldHash(bytes memory data) internal pure returns(bytes32){return bytes32(uint256(keccak256(data))&((uint256(1)<<248)-1));}
    function leaf(uint256 i,Pt memory p) internal pure returns(bytes32){return keccak256(abi.encodePacked(i,p.x,p.y));}
    struct Game {
        bytes32 record;bytes32 rc;bytes32 rd;DisputeContext context;
        uint256 dealerId;uint256 recipient;uint256 lo;uint256 hi;uint256 mid;uint256 deadline;
        address challenger;address dealer;Pt left;Pt rightC;Pt rightD;Pt midC;
        bool awaitingTrace;bool pending;bool done;
    }
    Game internal game;
    function beginGame(address caller,bytes32 id,bytes32 rc,uint256 cx,uint256 cy,bytes32[] calldata c0,bytes32[] calldata ct) external onlyLifecycle {
        require(admitted[id]&&!consistencySettled[id]&&(game.done||game.challenger==address(0)),InvalidState());
        Record storage r=records[id];DisputeContext memory context=lifecycle.disputeContext(r.nonce,r.dealer,r.recipient);uint256 t=context.ts>context.tt?context.ts:context.tt;
        require(stake[caller]>=5&&stake[context.account]>=5&&caller!=context.account,InvalidState());stake[caller]-=5;
        Pt memory c=Pt(cx,cy);
        if(eq(c,r.evaluation)||!lifecycle.member(rc,leaf(0,Pt(0,0)),0,c0)||!lifecycle.member(rc,leaf(t,c),t,ct)){
            credit[context.account]+=5;forfeited+=5;emit Verdict(id,12,false);return;
        }
        stake[context.account]-=5;
        game=Game(id,rc,0,context,r.dealer,r.recipient,0,t,0,block.timestamp+roundSeconds,caller,context.account,Pt(0,0),c,r.evaluation,Pt(0,0),true,false,false);
        emit GameOpened(id,caller,context.account,game.deadline);
    }
    function respondGame(address caller,bytes32 rd,bytes32[] calldata d0,bytes32[] calldata dt) external onlyLifecycle {
        Game storage a=game;require(!a.done&&a.awaitingTrace&&caller==a.dealer&&block.timestamp<=a.deadline,InvalidState());
        if(!lifecycle.member(rd,leaf(0,Pt(0,0)),0,d0)||!lifecycle.member(rd,leaf(a.hi,a.rightD),a.hi,dt)){settleGame(true,false);emit Verdict(a.record,13,false);return;}
        a.rd=rd;a.awaitingTrace=false;a.deadline=block.timestamp+roundSeconds;emit DealerTrace(a.record,rd,a.deadline);
    }
    function move(address caller,uint256 x,uint256 y,bytes32[] calldata proof) external onlyLifecycle {
        Game storage a=game;require(!a.done&&!a.awaitingTrace&&a.hi>a.lo+1&&block.timestamp<=a.deadline,InvalidState());uint256 mid=(a.lo+a.hi)/2;Pt memory p=Pt(x,y);
        if(!a.pending){require(caller==a.challenger,InvalidState());if(!lifecycle.member(a.rc,leaf(mid,p),mid,proof)){settleGame(false,true);emit Verdict(a.record,14,false);return;}a.midC=p;a.mid=mid;a.pending=true;}
        else{require(caller==a.dealer,InvalidState());if(!lifecycle.member(a.rd,leaf(mid,p),mid,proof)){settleGame(true,false);emit Verdict(a.record,14,false);return;}if(eq(p,a.midC)){a.lo=mid;a.left=p;}else{a.hi=mid;a.rightC=a.midC;a.rightD=p;}a.pending=false;}a.deadline=block.timestamp+roundSeconds;
    }
    function finishGame(uint256 sx,uint256 sy,uint256 tx_,uint256 ty,bytes32[] calldata sp,bytes32[] calldata tp,uint256 recordCount,bytes32[] calldata sourcePath,bytes32[] calldata targetPath) external onlyLifecycle {
        Game storage a=game;require(!a.done&&!a.awaitingTrace&&!a.pending&&a.hi==a.lo+1&&block.timestamp<=a.deadline,InvalidState());
        Pt memory s;Pt memory t;
        if(a.lo<a.context.ts){
            bytes32 sourceLeaf=fieldHash(abi.encodePacked("VESS-VECTOR-v1",a.context.source,a.dealerId,a.context.src));
            require(lifecycle.recordMember(a.context.anchor,sourceLeaf,recordCount+a.dealerId-1,sourcePath),InvalidState());
            s=Pt(sx,sy);require(lifecycle.member(a.context.src,leaf(a.lo,s),a.lo,sp),InvalidState());
        }else require(sx==0&&sy==0&&sp.length==0&&sourcePath.length==0,InvalidState());
        if(a.lo<a.context.tt){
            bytes32 targetLeaf=fieldHash(abi.encodePacked("VESS-VECTOR-v1",a.context.target,a.dealerId,a.context.tgt));
            require(lifecycle.recordMember(a.context.anchor,targetLeaf,recordCount+a.context.n+a.dealerId-1,targetPath),InvalidState());
            t=Pt(tx_,ty);require(lifecycle.member(a.context.tgt,leaf(a.lo,t),a.lo,tp),InvalidState());
        }else require(tx_==0&&ty==0&&tp.length==0&&targetPath.length==0,InvalidState());
        Pt memory next=add(a.left,mul(add(t,neg(s)),pow(a.recipient,a.lo)));bool c=eq(next,a.rightC);bool d=eq(next,a.rightD);
        settleGame(c,d);emit Verdict(a.record,c?(d?6:4):(d?5:7),d);
    }
    function settleGame(bool c,bool d) internal {
        game.done=true;consistencySettled[game.record]=true;
        if(c&&d){credit[game.challenger]+=5;credit[game.dealer]+=5;}else if(c){credit[game.challenger]+=10;}else if(d){credit[game.dealer]+=10;}else burned+=10;
    }
    function gameTimeout() external onlyLifecycle {
        require(game.challenger!=address(0)&&!game.done&&block.timestamp>game.deadline,InvalidState());bool dealerMissing=game.awaitingTrace||game.pending;
        settleGame(dealerMissing,!dealerMissing);emit Verdict(game.record,8,false);
    }
    struct Availability {uint256 nonce;uint256 dealerId;uint256 recipient;uint256 deadline;address dealer;address claimant;bool done;}
    mapping(bytes32=>Availability) public availability;
    function obligationKey(uint256 nonce,uint256 dealer,uint256 recipient) public pure returns(bytes32){return keccak256(abi.encodePacked("VESS-DA-OBLIGATION-v1",nonce,dealer,recipient));}
    function openDA(address caller,uint256 nonce,uint256 dealer,uint256 recipient,uint256 rx,uint256 ry,uint256 s) external payable onlyLifecycle {
        require(msg.value==15,InvalidState());bytes32 key=obligationKey(nonce,dealer,recipient);require(availability[key].claimant==address(0),InvalidState());
        DisputeContext memory context;bool valid;
        try lifecycle.disputeContext(nonce,dealer,recipient) returns(DisputeContext memory c){context=c;valid=c.required&&block.timestamp+responseSeconds<=c.expiry;}catch{}
        bool authorized;try lifecycle.verifyDA(caller,nonce,dealer,recipient,rx,ry,s) returns(bool ok){authorized=ok;}catch{}
        if(!valid||!authorized){address account=context.account;if(account==address(0))account=lifecycle.dealerAccount(dealer);credit[caller]+=10;claimantLoss(caller,account,key,9);return;}
        require(stake[context.account]>=100,InvalidState());stake[context.account]-=100;
        availability[key]=Availability(nonce,dealer,recipient,block.timestamp+responseSeconds,context.account,caller,false);
        emit DAOpened(key,nonce,dealer,recipient,block.timestamp+responseSeconds);
    }
    function answerDA(address caller,bytes32 key,bytes calldata raw,uint256 index,bytes32[] calldata path) external onlyLifecycle {
        Availability storage a=availability[key];require(a.claimant!=address(0)&&!a.done&&caller==a.dealer&&block.timestamp<=a.deadline,InvalidState());
        require(lifecycle.verifyDAResponse(a.nonce,a.dealerId,a.recipient,raw,index,path),InvalidState());emit DABytes(key,raw);a.done=true;stake[a.dealer]+=100;credit[a.claimant]+=5;credit[a.dealer]+=6;bondsReturned+=5;servicePaid+=6;burned+=4;
    }
    function defaultDA(bytes32 key) external onlyLifecycle {
        Availability storage a=availability[key];require(a.claimant!=address(0)&&!a.done&&block.timestamp>a.deadline,InvalidState());a.done=true;credit[a.claimant]+=55;finderPaid+=40;burned+=60;bondsReturned+=5;
    }
}
