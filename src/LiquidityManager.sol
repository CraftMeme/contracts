// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {CurrencyLibrary, Currency} from "v4-core/src/types/Currency.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {VestingContract} from "./VestingContract.sol";

contract LiquidityManager {
    /**
     * @notice Errors.
     */
    error PoolAlreadyInitialized();
    error PoolNotInitialized();

    using SafeERC20 for IERC20;
    using CurrencyLibrary for Currency;

    /**
     * @notice Variables.
     */
    IPoolManager public poolManager;
    VestingContract public vestingContract;
    uint256 public liquidityThreshold = 2 * 1e6; // 20 USDT or USDC

    /**
     * @notice Structs.
     */
    struct LiquidityProvider {
        uint256 amountProvided;
        bool hasVested;
    }

    /**
     * @notice Events.
     */
    event PoolInitialized(
        address indexed token0,
        address indexed token1,
        address indexed pool
    );
    event LiquidityAdded(
        address indexed provider,
        address indexed token0,
        address indexed token1,
        uint256 amount
    );
    event LiquidityThresholdReached(
        address indexed token0,
        address indexed token1
    );

    /**
     * @notice Mappings.
     */
    /**
     * @dev Mapping of liquidity providers to tokens they provided liquidity for.
     */
    mapping(address => mapping(address => LiquidityProvider))
        public liquidityProviders;
    mapping(address => bool) public poolInitialized;

    constructor(address _poolManager, address _vestingContract) {
        poolManager = IPoolManager(_poolManager);
        vestingContract = VestingContract(_vestingContract);
    }

    /**
     * @notice Initializes a new Uniswap V4 pool.
     */
    function initializePool(
        address token0,
        address token1,
        uint24 swapFee,
        int24 tickSpacing,
        uint160 startingPrice
    ) external {
        require(!poolInitialized[token0], PoolAlreadyInitialized());
        if (token0 > token1) {
            (token0, token1) = (token1, token0);
        }

        PoolKey memory poolKey = PoolKey({
            currency0: Currency.wrap(token0),
            currency1: Currency.wrap(token1),
            fee: swapFee,
            tickSpacing: tickSpacing,
            hooks: IHooks(address(0)) // Hookless pool
        });

        poolManager.initialize(poolKey, startingPrice);
        poolInitialized[token0] = true;
        poolInitialized[token1] = true;
        emit PoolInitialized(token0, token1, address(poolManager));
    }

    /**
     * @notice Adds liquidity to an existing Uniswap V4 pool.
     */
    function addLiquidity(
        address token0,
        address token1,
        uint24 swapFee,
        int24 tickLower,
        int24 tickUpper,
        uint256 amountToken0,
        uint256 amountToken1
    ) external {
        require(poolInitialized[token0], PoolNotInitialized());

        IERC20(token0).safeTransferFrom(
            msg.sender,
            address(this),
            amountToken0
        );
        IERC20(token1).safeTransferFrom(
            msg.sender,
            address(this),
            amountToken1
        );

        uint256 totalLiquidity = amountToken0 + amountToken1;
        liquidityProviders[msg.sender][token0].amountProvided += totalLiquidity;

        if (
            liquidityProviders[msg.sender][token0].amountProvided >=
            liquidityThreshold
        ) {
            emit LiquidityThresholdReached(token0, token1);

            vestingContract.setVestingSchedule(
                msg.sender,
                token0,
                block.timestamp,
                8 * 30 days,
                totalLiquidity
            );
            liquidityProviders[msg.sender][token0].hasVested = true;
        }

        emit LiquidityAdded(msg.sender, token0, token1, totalLiquidity);
    }

    /**
     * @notice Claims tokens that investors have vested.
     */
    function claimVestedTokens() external {
        vestingContract.release(msg.sender);
    }

    /**
     * @notice Checks if the liquidity threshold for a token has been met.
     * @param token Address of the token to check.
     */
    function isThresholdMet(address token) external view returns (bool) {
        return
            liquidityProviders[msg.sender][token].amountProvided >=
            liquidityThreshold;
    }
}
