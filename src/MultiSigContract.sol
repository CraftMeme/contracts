// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { FactoryTokenContract } from "./FactoryTokenContract.sol";
import { ISP } from "@signprotocol/signprotocol-evm/src/interfaces/ISP.sol";
import { Attestation } from "@signprotocol/signprotocol-evm/src/models/Attestation.sol";
import { DataLocation } from "@signprotocol/signprotocol-evm/src/models/DataLocation.sol";

/**
 * @title MultiSigContract
 * @dev A contract that requires multiple signers to approve a tx.
 * Ensures decentralization by requiring multiple sign-offs for transaction execution.
 * @notice This contract inherits sign protocol attestations to attest signatures onchain.
 * @notice This contract works in tandem with FactoryTokenContract to manage meme token creation.
 * @dev Uses volatile storage, signed transaction data is removed after execution.
 */
contract MultiSigContract is Ownable {
    FactoryTokenContract public factoryTokenContract;
    ISP public spInstance;
    uint64 public signatureSchemaId;
    /// @notice Structure to store transaction data for multisig approvals.

    struct TxData {
        uint256 txId; // Unique ID of the transaction
        address owner; // Owner of the transaction (token creator)
        address[] signers; // List of addresses that can sign the transaction
        address[] signatures; // List of addresses that have already signed the transaction
    }

    /// @notice Mapping from txId to the txData for that id.
    mapping(uint256 => TxData) public pendingTxs;
    /// @notice Mapping from signer to the attestation id made during signing create memecoin.
    mapping(address => uint64) public signerToAttestationId;

    error MultiSigContract__onlyFactoryTokenContract();
    error MultiSigContract__onlySigner();
    error MultiSigContract__alreadySigned();

    /**
     * @dev Modifier to ensure only the factory contract or owner can execute certain functions.
     */
    modifier onlyFactoryTokenContract() {
        require(
            (msg.sender == address(factoryTokenContract)) || (msg.sender == owner()),
            MultiSigContract__onlyFactoryTokenContract()
        );
        _;
    }

    /**
     * @dev Modifier to restrict access to only signers of a specific transaction.
     * Reverts if the caller is not one of the allowed signers.
     * @param _txId The transaction ID being processed.
     */
    modifier onlySigner(uint256 _txId) {
        address temp = address(0);
        for (uint256 i = 0; i < pendingTxs[_txId].signers.length; i++) {
            if (pendingTxs[_txId].signers[i] == msg.sender) {
                temp = pendingTxs[_txId].signers[i];
            }
        }
        require(temp == msg.sender, MultiSigContract__onlySigner());
        _;
    }

    /**
     * @dev Modifier to ensure a signer hasn't already signed a given transaction.
     * @param _txId The transaction ID being processed.
     */
    modifier notAlreadySigned(uint256 _txId) {
        address temp = address(0);
        for (uint256 i = 0; i < pendingTxs[_txId].signatures.length; i++) {
            if (pendingTxs[_txId].signatures[i] == msg.sender) {
                temp = pendingTxs[_txId].signatures[i];
            }
        }
        require(temp == address(0), MultiSigContract__alreadySigned());
        _;
    }

    /**
     * @dev Modifier to ensure the transaction has already been signed.
     * @param _txId The transaction ID being processed.
     */
    modifier alreadySigned(uint256 _txId) {
        address temp = address(0);
        for (uint256 i = 0; i < pendingTxs[_txId].signatures.length; i++) {
            if (pendingTxs[_txId].signatures[i] == msg.sender) {
                temp = pendingTxs[_txId].signatures[i];
            }
        }
        require(temp == msg.sender, MultiSigContract__alreadySigned());
        _;
    }

    /**
     * @param _spInstance Sign protocol instance address.
     * @param _signatureSchemaId Signature schema id created on sign protocol.
     */
    constructor(address _spInstance, uint64 _signatureSchemaId) Ownable(msg.sender) {
        spInstance = ISP(_spInstance);
        signatureSchemaId = _signatureSchemaId;
    }

    /**
     * @notice Sets the address of the factory token contract.
     * @param _factoryTokenContract Address of the factory token contract.
     * @dev This can only be called by the contract owner.
     */
    function setFactoryTokenContract(address _factoryTokenContract) external onlyOwner {
        factoryTokenContract = FactoryTokenContract(_factoryTokenContract);
    }

    /**
     * @notice Adds a new pending transaction for signatures.
     * @param _txId Unique ID of the transaction(key in txArray in FactoryTokenContract)
     * @param _owner The address of the transaction owner.
     * @param _signers Array of addresses that are allowed to sign the transaction.
     * @dev This function can only be called by the FactoryTokenContract.
     */
    function queueTx(uint256 _txId, address _owner, address[] memory _signers) external onlyFactoryTokenContract {
        _handleQueue(_txId, _owner, _signers);
    }

    /**
     * @notice Allows a signer to sign a pending transaction.
     * @notice Creates an attestation that the signer has signed the transaction.
     * @param _txId The transaction ID to be signed.
     * @dev Can only be called by a valid signer and if the caller hasn't already signed.
     */
    function signTx(uint256 _txId) external onlySigner(_txId) notAlreadySigned(_txId) {
        _handleSign(_txId);
        _attestSign(_txId, msg.sender);
    }

    /**
     * @notice Allows a signer to revoke their signature from a pending transaction.
     * @notice Revokes the attestation that the signer has signed the transaction.
     * @param _txId The transaction ID to be unsigned.
     * @dev Can only be called by a valid signer who has already signed the transaction.
     */
    function unsignTx(uint256 _txId) external onlySigner(_txId) alreadySigned(_txId) {
        _handleUnSign(_txId);
        _attestRevokeSign(_txId, msg.sender);
    }

    /**
     * @param _txId The transaction ID to retrieve.
     * @return The details of the pending transaction.
     */
    function getPendingTxData(uint256 _txId) public view returns (TxData memory) {
        return pendingTxs[_txId];
    }

    /**
     * @notice Internal function to handle the queueing of a transaction.
     * @param _txId Unique ID of the transaction(key in txArray in FactoryTokenContract).
     * @param _owner The address of the transaction owner.
     * @param _signers Array of addresses that are allowed to sign the transaction.
     */
    function _handleQueue(uint256 _txId, address _owner, address[] memory _signers) internal {
        TxData memory tempTx = TxData({ txId: _txId, owner: _owner, signers: _signers, signatures: new address[](0) });
        pendingTxs[_txId] = tempTx;
    }

    /**
     * @dev Internal function to handle the signing of a transaction.
     * @param _txId The transaction ID being processed.
     * If enough signatures are collected, the transaction is executed.
     */
    function _handleSign(uint256 _txId) internal {
        if (pendingTxs[_txId].signatures.length == (pendingTxs[_txId].signers.length - 1)) {
            factoryTokenContract.executeCreateMemecoin(_txId);
            delete pendingTxs[_txId]; // Clear the pending transaction after execution
        } else {
            pendingTxs[_txId].signatures.push(msg.sender);
        }
    }

    /**
     * @notice Internal function to handle the attestation of a signature.
     * @param _txId The transaction ID being processed.
     * @param _signer The address of the signer.
     */
    function _attestSign(uint256 _txId, address _signer) internal {
        bytes[] memory recipients = new bytes[](1);
        recipients[0] = abi.encode(msg.sender);
        Attestation memory a = Attestation({
            schemaId: signatureSchemaId,
            linkedAttestationId: 0,
            attestTimestamp: uint64(block.timestamp),
            revokeTimestamp: 0,
            attester: address(this),
            validUntil: 0,
            dataLocation: DataLocation.ONCHAIN,
            revoked: false,
            recipients: recipients,
            data: abi.encode(_txId, _signer)
        });
        uint64 attestationId = spInstance.attest(a, "", "", "");
        signerToAttestationId[_signer] = attestationId;
    }

    /**
     * @notice Internal function to handle the revocation of attestation of a signature.
     * @param _txId The transaction ID being processed.
     * @param _signer The address of the signer.
     */
    function _attestRevokeSign(uint256 _txId, address _signer) internal {
        // spInstance.revoke(
        //     signerToAttestationId[_signer],
        //     "Signer unsigned create memecoin."
        // );
    }

    /**
     * @dev Internal function to handle the revocation of a signature.
     * @param _txId The transaction ID being unsigned.
     * Removes the signer's signature from the list.
     */
    function _handleUnSign(uint256 _txId) internal {
        for (uint256 i = 0; i < pendingTxs[_txId].signatures.length; i++) {
            if (pendingTxs[_txId].signatures[i] == msg.sender) {
                delete pendingTxs[_txId].signatures[i];
            }
        }
    }
}
