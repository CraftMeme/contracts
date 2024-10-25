// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {TokenContract} from "./helpers/TokenContract.sol";
import {MultiSigContract} from "./MultiSigContract.sol";
import {LiquidityManager} from "./LiquidityManager.sol";

/**
 * @title FactoryTokenContract.
 * @author CraftMeme.
 * @dev Has persistant storage, MultiSigContract has volatile storage.
 * @dev This means past signed txs data is available in this contract for more functions
 * after tx is executed.
 */
contract FactoryTokenContract is Ownable {
    error FactoryTokenContract__onlyMultiSigContract();
    error TransactionAlreadyExecuted();
    error InvalidSignerCount();
    error InvalidSupply();
    error EmptyName();
    error EmptySymbol();

    MultiSigContract public multiSigContract;
    LiquidityManager public liquidityManager;

    struct TxData {
        uint256 txId;
        address owner;
        address[] signers;
        bool isPending;
        string tokenName;
        string tokenSymbol;
        uint256 totalSupply;
        uint256 maxSupply;
        bool canMint;
        bool canBurn;
        bool supplyCapEnabled;
        address tokenAddress;
    }

    TxData[] public txArray;
    uint256 TX_ID;
    address private USDC_ADDRESS;
    mapping(address => uint256) public ownerToTxId;

    event TransactionQueued(
        uint256 indexed txId,
        address indexed owner,
        address[] signers,
        string tokenName,
        string tokenSymbol
    );

    event MemecoinCreated(
        address indexed owner,
        address indexed tokenAddress,
        string indexed name,
        string symbol,
        uint256 supply
    );

    modifier onlyMultiSigContract() {
        require(
            msg.sender == address(multiSigContract),
            FactoryTokenContract__onlyMultiSigContract()
        );
        _;
    }

    modifier onlyPendigTx(uint256 _txId) {
        require(txArray[_txId].isPending, TransactionAlreadyExecuted());
        _;
    }

    constructor(
        address _multiSigContract,
        address _liquidityManager,
        address initialOwner
    ) Ownable(initialOwner) {
        multiSigContract = MultiSigContract(_multiSigContract);
        liquidityManager = LiquidityManager(_liquidityManager);
        TxData memory constructorTx = TxData({
            txId: 0,
            owner: address(0),
            signers: new address[](0),
            isPending: true,
            tokenName: "",
            tokenSymbol: "",
            totalSupply: 0,
            maxSupply: 0,
            canMint: false,
            canBurn: false,
            supplyCapEnabled: false,
            tokenAddress: address(0)
        });
        txArray.push(constructorTx);
        ownerToTxId[address(0)] = 0;
        TX_ID = 1;
    }

    /**
     * @notice Only adds a pending tx to create a new memecoin.
     * @notice Tx is completed when all of the signers approve the tx in the MultiSigContract.
     * @dev Creates a new pending tx in MultiSigContract.
     * @dev When all the signers complete the signature in MultiSigContract, the MSC calls executeTx()
     * to complete the tx and create a new memecoin.
     * @dev This function does not add any liquidity or such, that is done by separate functions.
     * @dev One memecoin can only have one on paper owner, but the other owner's data is always saved
     * in this contract.
     */
    function queueCreateMemecoin(
        address[] memory _signers,
        address _owner,
        string memory _tokenName,
        string memory _tokenSymbol,
        uint256 _totalSupply,
        uint256 _maxSupply,
        bool _canMint,
        bool _canBurn,
        bool _supplyCapEnabled
    ) external returns (uint256 txId) {
        require(_signers.length >= 2, InvalidSignerCount());
        require(bytes(_tokenName).length > 0, EmptyName());
        require(bytes(_tokenSymbol).length > 0, EmptySymbol());
        require(_totalSupply > 0, InvalidSupply());
        if (_supplyCapEnabled) {
            require(_maxSupply >= _totalSupply, InvalidSupply());
        }
        txId = _handleQueue(
            _signers,
            _owner,
            _tokenName,
            _tokenSymbol,
            _totalSupply,
            _maxSupply,
            _canMint,
            _canBurn,
            _supplyCapEnabled
        );
    }

    /**
     * @notice Executes the pending tx in MultiSigContract after all signers have signed the tx.
     * @notice Memecoin has been created when this function is called.
     * @dev This function is only callable by the MultiSigContract.
     */
    function executeCreateMemecoin(
        uint256 _txId
    ) public onlyMultiSigContract onlyPendigTx(_txId) {
        _createMemecoin(_txId);
    }

    /**
     * @notice Gets the tx data of a transaction
     * @param _txId data of the transaction
     * @return TxData memory
     */
    function getTxData(uint256 _txId) external view returns (TxData memory) {
        return txArray[_txId];
    }

    function _handleQueue(
        address[] memory _signers,
        address _owner,
        string memory _tokenName,
        string memory _tokenSymbol,
        uint256 _totalSupply,
        uint256 _maxSupply,
        bool _canMint,
        bool _canBurn,
        bool _supplyCapEnabled
    ) internal returns (uint256 txId) {
        TxData memory tempTx = TxData({
            txId: TX_ID,
            owner: _owner,
            signers: _signers,
            isPending: true,
            tokenName: _tokenName,
            tokenSymbol: _tokenSymbol,
            totalSupply: _totalSupply,
            maxSupply: _maxSupply,
            canMint: _canMint,
            canBurn: _canBurn,
            supplyCapEnabled: _supplyCapEnabled,
            tokenAddress: address(0)
        });
        txArray.push(tempTx);
        ownerToTxId[_owner] = TX_ID;
        multiSigContract.queueTx(TX_ID, _owner, _signers);
        emit TransactionQueued(
            TX_ID,
            _owner,
            _signers,
            _tokenName,
            _tokenSymbol
        );
        txId = TX_ID;
        TX_ID += 1;
    }

    function _createMemecoin(
        uint256 _txId
    ) internal returns (TokenContract newToken) {
        TxData memory txData = txArray[_txId];
        // Deploy new TokenContract for the memecoin
        newToken = new TokenContract(
            txData.owner,
            txData.tokenName,
            txData.tokenSymbol,
            txData.totalSupply,
            txData.maxSupply,
            txData.canMint,
            txData.canBurn,
            txData.supplyCapEnabled
        );

        // Initialize the pool for the newly created token
        liquidityManager.initializePool(
            address(newToken),
            address(USDC_ADDRESS), // USDT/USDC address
            300, // swap fee (Uniswap's fee tiers: 0.01%->100, 0.05%->500, 0.3%->3000, 1%->10000)
            60, // tick spacing (depends on fee tier: 0.01%->1, 0.05%->10, 0.3%->60, 1%->200)
            79_228_162_514_264_337_593_543_950_336 // 0.0001 starting price (Q64.96 format)
        );

        txArray[_txId].isPending = false;
        txArray[_txId].tokenAddress = address(newToken);
        // Emit the MemecoinCreated event
        emit MemecoinCreated(
            txData.owner,
            address(newToken),
            txData.tokenName,
            txData.tokenSymbol,
            txData.totalSupply
        );
    }

    // Function to update LiquidityManager address, if needed
    function updateLiquidityManager(
        address _liquidityManager
    ) external onlyOwner {
        liquidityManager = LiquidityManager(_liquidityManager);
    }

    function getUSDCAddress() public view returns (address) {
        return USDC_ADDRESS;
    }
}
