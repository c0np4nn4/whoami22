// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// Independent BN254 research verifier. It is not the unavailable original contract.
contract VessBench {
    uint256 constant P=21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant Q=21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant BLS=52435875175126190479447740508185965837690552500527637822603658699938581184513;
    struct Pt{uint256 x;uint256 y;}
    Pt public H;
    address public immutable admin;
    mapping(uint256=>mapping(uint256=>Pt)) public dealerKeys;
    mapping(uint256=>uint256) public keyEpoch;mapping(uint256=>address) public dealerAccount;
    bytes32 public root;bytes32 public versioned;bytes32 public sourceRoot;bytes32 public targetRoot;
    uint256 public sourceT;uint256 public targetT;
    mapping(bytes32=>bool) public admitted;
    mapping(bytes32=>Pt) internal evals;
    mapping(bytes32=>uint256) internal recipients;
    event Verdict(bytes32 indexed record,uint256 kind,bool value);
    event Anchor(bytes32 root,bytes32 versioned);
    constructor(){admin=msg.sender;H=hashPoint(keccak256("VESS-BN-H-v1"));}
    function add(Pt memory a,Pt memory b) internal view returns(Pt memory r){uint256[4] memory input=[a.x,a.y,b.x,b.y];bool ok;assembly("memory-safe"){ok:=staticcall(gas(),6,input,128,r,64)}require(ok,"ecadd");}
    function mul(Pt memory a,uint256 s) internal view returns(Pt memory r){require(s<Q,"scalar");uint256[3] memory input=[a.x,a.y,s];bool ok;assembly("memory-safe"){ok:=staticcall(gas(),7,input,96,r,64)}require(ok,"ecmul");}
    function neg(Pt memory a) internal pure returns(Pt memory){return Pt(a.x,a.y==0?0:P-a.y);}
    function eq(Pt memory a,Pt memory b) internal pure returns(bool){return a.x==b.x&&a.y==b.y;}
    function base() internal pure returns(Pt memory){return Pt(1,2);}
    function modexp(uint256 a,uint256 e,uint256 m) public view returns(uint256 out){uint256[6] memory input=[uint256(32),32,32,a,e,m];uint256[1] memory result;bool ok;assembly("memory-safe"){ok:=staticcall(gas(),5,input,192,result,32)}require(ok,"modexp");return result[0];}
    function hashPoint(bytes32 seed) public view returns(Pt memory){uint256 x=uint256(seed)%P;for(uint256 i=0;i<256;i++){uint256 v=addmod(mulmod(mulmod(x,x,P),x,P),3,P);uint256 y=modexp(v,(P+1)/4,P);if(mulmod(y,y,P)==v){if(y%2==1)y=P-y;return Pt(x,y);}x=addmod(x,1,P);}revert("hashPoint bound");}
    function point(uint256[] calldata d,uint256 at) internal pure returns(Pt memory){return Pt(d[at],d[at+1]);}
    function register(uint256 id,uint256 epoch,uint256 x,uint256 y,address account) external {require(msg.sender==admin,"admin");require(epoch>=keyEpoch[id],"retired");Pt memory old=dealerKeys[id][epoch];require((old.x==0&&old.y==0)||(old.x==x&&old.y==y),"immutable historical key");require(x!=0||y!=0,"identity key");require(account!=address(0),"dealer account");dealerKeys[id][epoch]=Pt(x,y);keyEpoch[id]=epoch;dealerAccount[id]=account;}
    function anchorBlob(bytes32 r,bytes32 src,bytes32 tgt,uint256 t0,uint256 t1) external {require(msg.sender==admin,"admin");require(blobhash(0)!=0,"blob required");root=r;versioned=blobhash(0);sourceRoot=src;targetRoot=tgt;sourceT=t0;targetT=t1;emit Anchor(root,versioned);}
    function anchorCalldata(bytes calldata raw,bytes32 src,bytes32 tgt,uint256 t0,uint256 t1) external {require(msg.sender==admin,"admin");root=keccak256(raw);versioned=0;sourceRoot=src;targetRoot=tgt;sourceT=t0;targetT=t1;emit Anchor(root,0);}
    function publishVector(bytes calldata raw) external {emit Anchor(keccak256(raw),0);}
    mapping(bytes32=>bytes) public storedBytes;
    function storeVector(bytes32 key,bytes calldata raw) external {storedBytes[key]=raw;}
    function anchorBlobs(bytes32 summary,uint256 count) external {require(msg.sender==admin&&count>0,"admin/count");for(uint256 i=0;i<count;i++){require(blobhash(i)!=0,"missing blob");emit Anchor(summary,blobhash(i));}require(blobhash(count)==0,"blob count");}
    function fieldOpenings(bytes calldata proofs,bytes32 record,uint256 payloadLen) external view {require(proofs.length%192==0&&proofs.length/192==(payloadLen+30)/31,"field count");bytes memory raw=new bytes(payloadLen);uint256 omega=modexp(7,(BLS-1)/4096,BLS);for(uint256 i=0;i<proofs.length/192;i++){bytes calldata p=proofs[i*192:(i+1)*192];bytes32 vh;uint256 z;uint256 y;assembly("memory-safe"){vh:=calldataload(p.offset) z:=calldataload(add(p.offset,32)) y:=calldataload(add(p.offset,64))}uint256 index=i+2;uint256 reverse;for(uint256 b=0;b<12;b++){reverse=(reverse<<1)|(index&1);index>>=1;}require(vh==versioned&&z==modexp(omega,reverse,BLS)&&y<2**248,"field position/value");(bool ok,bytes memory output)=address(10).staticcall(p);require(ok&&output.length==64,"field KZG");for(uint256 j=0;j<31&&i*31+j<payloadLen;j++){raw[i*31+j]=bytes1(uint8(y>>(8*(30-j))));}}require(keccak256(raw)==record&&root==keccak256(abi.encodePacked(uint256(0),record)),"record binding");}
    function kzg(bytes calldata proof) public view returns(uint256 y){require(proof.length==192,"kzg length");bytes32 vh;uint256 z;assembly("memory-safe"){vh:=calldataload(proof.offset) z:=calldataload(add(proof.offset,32)) y:=calldataload(add(proof.offset,64))}require(vh==versioned,"versioned hash");require(z==1||z==BLS-1,"root slot");(bool ok,bytes memory output)=address(10).staticcall(proof);require(ok&&output.length==64,"KZG");}
    function rootOpening(bytes calldata p0,bytes calldata p1) public view {require(versioned!=0,"blob anchor");uint256 z0;uint256 z1;assembly("memory-safe"){z0:=calldataload(add(p0.offset,32)) z1:=calldataload(add(p1.offset,32))}require(z0==1&&z1==BLS-1,"slot order");uint256 a=kzg(p0);uint256 b=kzg(p1);require(a<2**128&&b<2**128,"root limb");require(bytes32((a<<128)|b)==root,"root binding");}
    function member(bytes32 r,bytes32 leaf,uint256 index,bytes32[] calldata path) public pure returns(bool){bytes32 v=leaf;for(uint256 i=0;i<path.length;i++){v=index%2==0?keccak256(abi.encodePacked(v,path[i])):keccak256(abi.encodePacked(path[i],v));index/=2;}return index==0&&v==r;}
    function adHash(uint256[] calldata r) public pure returns(bytes32){require(r.length==25,"record length");return keccak256(abi.encodePacked(r[:14]));}
    function recordHash(uint256[] calldata r) public pure returns(bytes32){return keccak256(abi.encodePacked(r));}
    function signature(uint256[] calldata r) public view returns(bool){Pt memory pk=dealerKeys[r[0]][r[4]];require(pk.x!=0||pk.y!=0,"registered key");uint256 c=uint256(keccak256(abi.encodePacked("BN-SIG-v1",pk.x,pk.y,r[22],r[23],keccak256(abi.encodePacked(r[:22])))))%Q;return eq(mul(base(),r[24]),add(point(r,22),mul(pk,c)));}
    function dleq(Pt memory b2,Pt memory p1,Pt memory p2,bytes32 context,uint256 c,uint256 s) internal view returns(bool){require(c<Q&&s<Q,"proof scalar");require(p1.x!=0||p1.y!=0,"identity public");require(p2.x!=0||p2.y!=0,"identity shared");Pt memory a=add(mul(base(),s),neg(mul(p1,c)));Pt memory b=add(mul(b2,s),neg(mul(p2,c)));return c==uint256(keccak256(abi.encodePacked("BN-DLEQ-v1",context,b2.x,b2.y,p1.x,p1.y,p2.x,p2.y,a.x,a.y,b.x,b.y)))%Q;}
    function pop(uint256[] calldata r) public view returns(bool){bytes32 ad=adHash(r);Pt memory hp=hashPoint(keccak256(abi.encodePacked("epk-pop",ad,r[14],r[15])));return dleq(hp,point(r,14),point(r,16),ad,r[18],r[19]);}
    function authenticated(uint256[] calldata r,uint256 index,bytes32[] calldata path) internal view returns(bytes32 id){require(r.length==25&&r[0]>0&&r[1]>0&&r[3]==0&&r[20]<Q&&r[21]<Q,"record");require(r[7]==uint256(sourceRoot)&&r[8]==uint256(targetRoot),"state roots");id=recordHash(r);require(member(root,keccak256(abi.encodePacked(index,id)),index,path),"membership");require(signature(r),"signature");}
    function admitRecord(uint256[] calldata r,uint256 index,bytes32[] calldata path,bytes calldata p0,bytes calldata p1) external returns(bytes32 id){rootOpening(p0,p1);id=authenticated(r,index,path);require(r[4]==keyEpoch[r[0]],"new admission retired key");require(!admitted[id],"duplicate");require(pop(r),"PoP");admitted[id]=true;evals[id]=point(r,10);recipients[id]=r[1];emit Verdict(id,0,true);}
    function plaintext(uint256[] calldata r,uint256[] calldata dp,uint256 index,bytes32[] calldata path,bytes calldata p0,bytes calldata p1) external payable returns(bool){require(msg.value==5,"complaint bond");rootOpening(p0,p1);bytes32 id=authenticated(r,index,path);if(!pop(r)){settleComplaint(r[0],false);emit Verdict(id,1,false);return false;}require(dp.length==4,"decryption proof");bytes32 context=keccak256(abi.encodePacked("DEC",adHash(r),r[14],r[15],r[20],r[21]));require(dleq(point(r,14),point(r,12),point(dp,0),context,dp[2],dp[3]),"decryption proof");
        uint256 kv=uint256(keccak256(abi.encodePacked("derive-key-0",adHash(r),r[1],r[12],r[13],r[14],r[15],dp[0],dp[1])))%Q;
        uint256 kr=uint256(keccak256(abi.encodePacked("derive-key-1",adHash(r),r[1],r[12],r[13],r[14],r[15],dp[0],dp[1])))%Q;
        Pt memory got=add(mul(base(),addmod(r[20],Q-kv,Q)),mul(H,addmod(r[21],Q-kr,Q)));bool good=eq(got,point(r,10));settleComplaint(r[0],good);emit Verdict(id,2,good);return good;
    }
    function fullVector(uint256[] calldata points,uint256 recipient,uint256 ex,uint256 ey) external returns(bool){require(points.length%2==0,"points");Pt memory value;uint256 power=1;for(uint256 i=0;i<points.length;i+=2){value=add(value,mul(point(points,i),power));power=mulmod(power,recipient,Q);}bool good=eq(value,Pt(ex,ey));emit Verdict(0,3,good);return good;}
    function settleComplaint(uint256 dealer,bool recordGood) internal {if(recordGood){burned+=5;forfeited+=5;}else{address account=dealerAccount[dealer];require(stake[account]>=10,"complaint stake");stake[account]-=10;credit[msg.sender]+=9;finderPaid+=4;burned+=6;bondsReturned+=5;}}
    struct Game{bytes32 rc;bytes32 rd;bytes32 record;bytes32 src;bytes32 tgt;uint256 ts;uint256 tt;uint256 lo;uint256 hi;uint256 mid;uint256 deadline;uint256 roundTime;address challenger;address dealer;Pt left;Pt rightC;Pt rightD;Pt midC;bool pending;bool done;}
    Game internal game;
    function traceLeaf(uint256 i,Pt memory v) internal pure returns(bytes32){return keccak256(abi.encodePacked(i,v.x,v.y));}
    function beginGame(bytes32 id,bytes32 rc,bytes32 rd,uint256 cx,uint256 cy,bytes32[] calldata c0,bytes32[] calldata ct,bytes32[] calldata d0,bytes32[] calldata dt,address dealer,uint256 roundTime) external {require(admitted[id],"admitted record");require(game.done||game.challenger==address(0),"active game");uint256 t=sourceT>targetT?sourceT:targetT;Pt memory e=evals[id];Pt memory c=Pt(cx,cy);require(!eq(c,e),"no disagreement");require(member(rc,traceLeaf(0,Pt(0,0)),0,c0)&&member(rc,traceLeaf(t,c),t,ct),"challenger endpoints");require(member(rd,traceLeaf(0,Pt(0,0)),0,d0)&&member(rd,traceLeaf(t,e),t,dt),"dealer endpoints");
        require(stake[msg.sender]>=5&&stake[dealer]>=5,"game bonds");stake[msg.sender]-=5;stake[dealer]-=5;
        game=Game(rc,rd,id,sourceRoot,targetRoot,sourceT,targetT,0,t,0,block.timestamp+roundTime,roundTime,msg.sender,dealer,Pt(0,0),c,e,Pt(0,0),false,false);
    }
    function move(uint256 x,uint256 y,bytes32[] calldata proof) external {Game storage a=game;require(!a.done&&a.hi>a.lo+1&&block.timestamp<=a.deadline,"move deadline/state");uint256 mid=(a.lo+a.hi)/2;Pt memory p=Pt(x,y);
        if(!a.pending){require(msg.sender==a.challenger&&member(a.rc,traceLeaf(mid,p),mid,proof),"challenger move");a.midC=p;a.mid=mid;a.pending=true;}
        else{require(msg.sender==a.dealer&&member(a.rd,traceLeaf(mid,p),mid,proof),"dealer move");if(eq(p,a.midC)){a.lo=mid;a.left=p;}else{a.hi=mid;a.rightC=a.midC;a.rightD=p;}a.pending=false;}a.deadline=block.timestamp+a.roundTime;
    }
    function finishGame(uint256 sx,uint256 sy,uint256 tx_,uint256 ty,bytes32[] calldata sp,bytes32[] calldata tp) external {Game storage a=game;require(!a.done&&!a.pending&&a.hi==a.lo+1&&block.timestamp<=a.deadline,"final state/deadline");Pt memory s;Pt memory t;
        if(a.lo<a.ts){s=Pt(sx,sy);require(member(a.src,traceLeaf(a.lo,s),a.lo,sp),"source coefficient");}else{require(sx==0&&sy==0&&sp.length==0,"source padding");}
        if(a.lo<a.tt){t=Pt(tx_,ty);require(member(a.tgt,traceLeaf(a.lo,t),a.lo,tp),"target coefficient");}else{require(tx_==0&&ty==0&&tp.length==0,"target padding");}
        Pt memory next=add(a.left,mul(add(t,neg(s)),modexp(recipients[a.record],a.lo,Q)));bool c=eq(next,a.rightC);bool d=eq(next,a.rightD);a.done=true;settleGame(c,d);emit Verdict(a.record,c?(d?6:4):(d?5:7),d);
    }
    function settleGame(bool c,bool d) internal {if(c&&d){credit[game.challenger]+=5;credit[game.dealer]+=5;}else if(c){credit[game.challenger]+=10;}else if(d){credit[game.dealer]+=10;}else{burned+=10;}}
    function gameTimeout() external {require(!game.done&&block.timestamp>game.deadline,"timeout");game.done=true;settleGame(game.pending,!game.pending);emit Verdict(game.record,8,false);}
    struct Obligation{bytes32 root;bytes32 record;address dealer;uint256 expiry;bool exists;}
    struct Availability{uint256 deadline;address claimant;uint256 bond;bool done;}
    mapping(bytes32=>Obligation) public obligations;
    mapping(bytes32=>Availability) public availability;
    mapping(address=>uint256) public stake;
    mapping(address=>uint256) public credit;
    uint256 public burned;uint256 public finderPaid;uint256 public servicePaid;uint256 public bondsReturned;uint256 public forfeited;
    function deposit() external payable {stake[msg.sender]+=msg.value;}
    function oblige(bytes32 key,bytes32 record,address dealer,uint256 expiry) external {require(msg.sender==admin&&admitted[record]&&!obligations[key].exists,"finalized obligation");require(expiry>block.timestamp,"retention");obligations[key]=Obligation(root,record,dealer,expiry,true);}
    function openDA(bytes32 key,uint256 delay) external payable {Obligation storage o=obligations[key];require(msg.value==15,"fee");require(availability[key].claimant==address(0),"duplicate");if(!o.exists||block.timestamp+delay>o.expiry||stake[o.dealer]<100){credit[msg.sender]+=10;burned+=5;forfeited+=5;emit Verdict(key,9,false);return;}stake[o.dealer]-=100;availability[key]=Availability(block.timestamp+delay,msg.sender,5,false);}
    function answerDA(bytes32 key,bytes32 record,uint256 index,bytes32[] calldata path) external {Obligation storage o=obligations[key];Availability storage a=availability[key];require(a.claimant!=address(0)&&!a.done&&msg.sender==o.dealer&&block.timestamp<=a.deadline,"response");require(record==o.record&&member(o.root,keccak256(abi.encodePacked(index,record)),index,path),"response anchor");a.done=true;stake[o.dealer]+=100;credit[a.claimant]+=5;credit[o.dealer]+=6;bondsReturned+=5;servicePaid+=6;burned+=4;}
    function defaultDA(bytes32 key) external {Availability storage a=availability[key];require(a.claimant!=address(0)&&!a.done&&block.timestamp>a.deadline,"default");a.done=true;credit[a.claimant]+=55;finderPaid+=40;burned+=60;bondsReturned+=5;}
    function withdraw() external {uint256 value=credit[msg.sender];credit[msg.sender]=0;(bool ok,)=msg.sender.call{value:value}("");require(ok,"transfer");}

}

contract ReservationLog {
    struct State{bytes32 root;uint256 version;uint256 t;uint256 delta;uint256 rho;uint256 incomingCount;uint256 reservedCount;uint256 unionCount;bool exists;}
    mapping(bytes32=>State) public states;
    mapping(bytes32=>mapping(uint256=>bool)) public incoming;
    mapping(bytes32=>mapping(uint256=>bool)) public reserved;
    mapping(bytes32=>mapping(uint256=>bytes32)) public attempts;
    mapping(bytes32=>bool) public allowed;
    event Reserved(bytes32 indexed source,bytes32 indexed digest,uint256 version,bytes32 root);
    function initialize(bytes32 source,bytes32 root,uint256 t,uint256 delta,uint256 rho,uint256[] calldata off) external {require(!states[source].exists,"already initialized");uint256 unique;for(uint256 i=0;i<off.length;i++){require(!incoming[source][off[i]],"duplicate");incoming[source][off[i]]=true;unique++;}require(delta+unique<t,"initial budget");states[source]=State(root,0,t,delta,rho,unique,0,unique,true);}
    function reserve(bytes32 source,bytes32 oldRoot,bytes32 newRoot,bytes32 digest,uint256 nonce,uint256 targetT,uint256 targetRho,uint256 eligible,uint256[] calldata off,bool difference) external {State storage s=states[source];require(s.exists&&s.root==oldRoot,"stale root");require(s.delta+off.length+targetRho<targetT&&eligible>=targetT,"target precheck");require(attempts[source][nonce]==0,"nonce");
        if(difference){for(uint256 i=0;i<off.length;i++){if(!reserved[source][off[i]]){reserved[source][off[i]]=true;s.reservedCount++;if(!incoming[source][off[i]])s.unionCount++;}}require(s.delta+s.unionCount<s.t&&s.reservedCount<=s.rho,"source budget");}
        s.root=newRoot;s.version++;attempts[source][nonce]=digest;allowed[digest]=true;emit Reserved(source,digest,s.version,newRoot);
    }
}
