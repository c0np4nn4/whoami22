// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface GenerationHost {
    function committeeN() external view returns(uint256);
    function committeeF() external view returns(uint256);
    function dealerAccount(uint256 id) external view returns(address);
}

/// Authenticated immutable generation bulletin board. Only the lifecycle
/// contract may forward calls; it preserves the original publisher identity.
contract E2EGeneration {
    address public immutable host;
    uint256 public roundSeconds;
    address public owner;
    bytes public initialConstant;
    struct Round {uint256 count;uint256 deadline;bool closed;mapping(uint256=>bytes) messages;}
    mapping(uint256=>mapping(uint256=>Round)) internal rounds;
    mapping(uint256=>bool) public opened;
    event GenerationBroadcast(uint256 indexed nonce,uint256 indexed phase,uint256 indexed dealer,bytes32 payloadHash);
    event GenerationClosed(uint256 indexed nonce,uint256 indexed phase,uint256 count);
    constructor(address host_){host=host_;}
    modifier onlyHost(){require(msg.sender==host,"generation host");_;}
    function configure(uint256 seconds_) external onlyHost {require(roundSeconds==0&&seconds_>0,"generation setup");roundSeconds=seconds_;}
    function open(uint256 nonce) external onlyHost {require(roundSeconds>0&&!opened[nonce],"generation open");opened[nonce]=true;}
    function setOwner(address owner_) external onlyHost {require(owner==address(0)&&owner_!=address(0),"generation owner");owner=owner_;}
    function publishInitial(address sender,bytes calldata payload) external onlyHost {
        require(sender==owner&&opened[0]&&initialConstant.length==0&&payload.length>0,"initial constant broadcast");
        initialConstant=payload;emit GenerationBroadcast(0,4,0,keccak256(payload));
    }
    function publish(address sender,uint256 nonce,uint256 phase,uint256 id,bytes calldata payload) external onlyHost {
        uint256 n=GenerationHost(host).committeeN();
        require(opened[nonce]&&roundSeconds>0&&phase<4&&id>0&&id<=n&&sender==GenerationHost(host).dealerAccount(id),"generation sender");
        require(nonce!=0||initialConstant.length!=0,"owner constant first");
        require(phase==0||rounds[nonce][phase-1].closed,"generation phase order");
        Round storage r=rounds[nonce][phase];
        if(r.messages[id].length!=0){require(keccak256(r.messages[id])==keccak256(payload),"broadcast equivocation");return;}
        require(!r.closed&&payload.length>0,"closed/empty broadcast");
        if(r.deadline==0)r.deadline=block.timestamp+roundSeconds;
        require(block.timestamp<=r.deadline,"broadcast deadline");
        r.messages[id]=payload;r.count++;emit GenerationBroadcast(nonce,phase,id,keccak256(payload));
        if(r.count==n){r.closed=true;emit GenerationClosed(nonce,phase,r.count);}
    }
    function close(uint256 nonce,uint256 phase) external onlyHost {
        require(phase<4,"generation phase");Round storage r=rounds[nonce][phase];if(r.closed)return;
        require(r.deadline!=0&&block.timestamp>r.deadline&&r.count>=GenerationHost(host).committeeN()-GenerationHost(host).committeeF(),"generation deadline/quorum");
        r.closed=true;emit GenerationClosed(nonce,phase,r.count);
    }
    function phase(uint256 nonce,uint256 index) external view returns(uint256,uint256,bool){Round storage r=rounds[nonce][index];return(r.count,r.deadline,r.closed);}
    function message(uint256 nonce,uint256 index,uint256 id) external view returns(bytes memory){require(rounds[nonce][index].closed,"unfrozen generation transcript");return rounds[nonce][index].messages[id];}
}
