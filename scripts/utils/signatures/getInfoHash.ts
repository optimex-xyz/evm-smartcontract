import { BytesLike, AddressLike, AbiCoder, keccak256 } from "ethers";
import { ITypes } from "../../../typechain-types/contracts/BTCEVM";

const abiCoder = AbiCoder.defaultAbiCoder();

export function getPresignHash(
  pmmRecvAddress: AddressLike,
  amountIn: bigint,
): string {
  const infoHash: string = keccak256(
    abiCoder.encode(["address", "uint256"], [pmmRecvAddress, amountIn]),
  );

  return infoHash;
}

export function getDepositConfirmationHash(
  amountIn: bigint,
  fromChain: [BytesLike, BytesLike, BytesLike],
  depositTxId: BytesLike,
  depositFromList: BytesLike[],
): string {
  const depositHash: string = keccak256(
    abiCoder.encode(
      ["uint256", "bytes[3]", "bytes[]"],
      [amountIn, fromChain, depositFromList],
    ),
  );
  const infoHash: string = keccak256(
    abiCoder.encode(["bytes32", "bytes"], [depositHash, depositTxId]),
  );

  return infoHash;
}

export function getSelectPMMHash(
  pmmId: BytesLike,
  pmmRecvAddress: BytesLike,
  toChain: BytesLike,
  toToken: BytesLike,
  amountOut: bigint,
  expiry: bigint,
): string {
  const infoHash: string = keccak256(
    abiCoder.encode(
      ["bytes32", "bytes", "bytes", "bytes", "uint256", "uint256"],
      [pmmId, pmmRecvAddress, toChain, toToken, amountOut, expiry],
    ),
  );

  return infoHash;
}

export function getRFQHash(
  minAmountOut: bigint,
  tradeTimeout: bigint,
  affiliate: ITypes.AffiliateStruct,
): string {
  const infoHash: string = keccak256(
    abiCoder.encode(
      ["uint256", "uint256", "tuple(uint256,string,bytes)"],
      [minAmountOut, tradeTimeout, Object.values(affiliate)],
    ),
  );

  return infoHash;
}

export function getMakePaymentHash(
  tradeIds: BytesLike[],
  signedAt: bigint,
  startIdx: bigint,
  paymentTxId: BytesLike,
): string {
  const bundlerHash: string = keccak256(
    abiCoder.encode(["bytes32[]"], [tradeIds]),
  );
  const infoHash: string = keccak256(
    abiCoder.encode(
      ["uint64", "uint256", "bytes32", "bytes"],
      [signedAt, startIdx, bundlerHash, paymentTxId],
    ),
  );

  return infoHash;
}

//  The function can be using for BTC->EVM, BTC->SOL, EVM->BTC, and SOL->BTC
//  For BTC->EVM, BTC->SOL, `totalFee != 0`
//  For EVM->BTC, and SOL->BTC, `totalFee = 0`
export function getConfirmPaymentHash(
  totalFee: bigint,
  paymentAmount: bigint,
  toChain: [BytesLike, BytesLike, BytesLike],
  paymentTxId: BytesLike,
): string {
  const paymentHash: string = keccak256(
    abiCoder.encode(
      ["uint256", "uint256", "bytes[3]"],
      [totalFee, paymentAmount, toChain],
    ),
  );
  const infoHash: string = keccak256(
    abiCoder.encode(["bytes32", "bytes"], [paymentHash, paymentTxId]),
  );

  return infoHash;
}

//  The function can be using for BTC->EVM, BTC->SOL, EVM->BTC, and SOL->BTC
//  For BTC->EVM, BTC->SOL, `totalFee = 0`
//  For EVM->BTC, and SOL->BTC, `totalFee != 0`
export function getConfirmSettlementHash(
  totalFee: bigint,
  releaseTxId: BytesLike,
): string {
  const infoHash: string = keccak256(
    abiCoder.encode(["uint256", "bytes"], [totalFee, releaseTxId]),
  );

  return infoHash;
}
