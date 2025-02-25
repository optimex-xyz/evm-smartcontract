import { AbiCoder, sha256 } from "ethers";
import { ITypes } from "../../../typechain-types/contracts/BTCEVM";

const abiCoder = AbiCoder.defaultAbiCoder();

export default function getTradeId(
  sessionId: bigint,
  solverAddress: string,
  tradeInfo: ITypes.TradeInfoStruct,
): string {
  const encodedData: string = abiCoder.encode(
    ["uint256", "address", "tuple(uint256,bytes[3],bytes[3])"],
    [sessionId, solverAddress, Object.values(tradeInfo)],
  );

  return sha256(encodedData);
}
