// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// Ordered blob batches for one authenticated bundle. Payload serialization is
/// checked by readers; the EVM checks every blob's opening to the common root.
contract E2EPublication {
    error InvalidPublication();
    uint256 constant P = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 public constant PAYLOAD_BYTES = 4095 * 31;
    address public immutable host;
    struct Progress {
        bytes32 root;
        bytes32 metadata;
        uint256 length;
        bytes32[] versions;
    }
    mapping(uint256 => Progress) internal entries;
    event BlobStored(uint256 indexed nonce, uint256 indexed index, bytes32 versioned);

    constructor(address host_) { host = host_; }

    function modexp(uint256 a,uint256 e,uint256 m) internal view returns(uint256) {
        uint256[6] memory input=[uint256(32),32,32,a,e,m];uint256[1] memory result;bool ok;
        assembly("memory-safe"){ok:=staticcall(gas(),5,input,192,result,32)}
        require(ok,InvalidPublication());return result[0];
    }
    function hashPoint(bytes32 seed) external view returns(uint256 x,uint256 y) {
        x=uint256(seed)%P;
        for(uint256 i=0;i<256;i++) {
            uint256 v=addmod(mulmod(mulmod(x,x,P),x,P),3,P);y=modexp(v,(P+1)/4,P);
            if(mulmod(y,y,P)==v){if(y%2==1)y=P-y;return(x,y);}
            x=addmod(x,1,P);
        }
        revert InvalidPublication();
    }

    function verifyRoot(bytes32 root, bytes32 version, bytes calldata proof) public view {
        require(version != 0 && uint256(root) < (uint256(1) << 248) && proof.length == 192, InvalidPublication());
        bytes32 vh; uint256 z; bytes32 y;
        assembly ("memory-safe") {
            vh := calldataload(proof.offset)
            z := calldataload(add(proof.offset, 32))
            y := calldataload(add(proof.offset, 64))
        }
        require(vh == version && z == 1 && y == root, InvalidPublication());
        (bool ok, bytes memory output) = address(10).staticcall(proof);
        require(ok && output.length == 64 && abi.decode(output, (uint256)) == 4096, InvalidPublication());
    }

    function append(uint256 nonce, bytes32 root, bytes32 metadata, uint256 length, uint256 offset, bytes calldata proofs) external returns(bytes32 first) {
        require(msg.sender == host && length > 0 && proofs.length > 0 && proofs.length % 192 == 0, InvalidPublication());
        Progress storage p = entries[nonce];
        uint256 count = proofs.length / 192;
        uint256 total = (length - 1) / PAYLOAD_BYTES + 1;
        require(offset == p.versions.length && count <= 9 && offset + count <= total, InvalidPublication());
        if (offset == 0) {
            p.root = root; p.metadata = metadata; p.length = length;
        } else {
            require(p.root == root && p.metadata == metadata && p.length == length, InvalidPublication());
        }
        require(blobhash(count) == 0, InvalidPublication());
        for (uint256 i; i < count; i++) {
            bytes32 version = blobhash(i);
            verifyRoot(root, version, proofs[i * 192:(i + 1) * 192]);
            p.versions.push(version);
            emit BlobStored(nonce, offset + i, version);
        }
        if (p.versions.length == total) return p.versions[0];
    }

    function progress(uint256 nonce) external view returns(bytes32, bytes32, uint256, uint256) {
        Progress storage p = entries[nonce];
        return (p.root, p.metadata, p.length, p.versions.length);
    }
    function versionAt(uint256 nonce, uint256 index) external view returns(bytes32) { return entries[nonce].versions[index]; }
    function member(bytes32 r,bytes32 leaf,uint256 index,bytes32[] calldata path) public pure returns(bool){bytes32 v=leaf;for(uint256 i=0;i<path.length;i++){v=index%2==0?keccak256(abi.encodePacked(v,path[i])):keccak256(abi.encodePacked(path[i],v));index/=2;}return index==0&&v==r;}
    function fieldHash(bytes memory data) internal pure returns(bytes32){return bytes32(uint256(keccak256(data))&((uint256(1)<<248)-1));}
    function recordMember(bytes32 r,bytes32 leaf,uint256 index,bytes32[] calldata path) public pure returns(bool){
        if(uint256(r)>=(uint256(1)<<248)||uint256(leaf)>=(uint256(1)<<248))return false;bytes32 v=leaf;for(uint256 i=0;i<path.length;i++){if(uint256(path[i])>=(uint256(1)<<248))return false;v=index%2==0?fieldHash(abi.encodePacked("VESS-MERKLE-v1",v,path[i])):fieldHash(abi.encodePacked("VESS-MERKLE-v1",path[i],v));index/=2;}return index==0&&v==r;
    }
}
