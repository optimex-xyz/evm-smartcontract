import { ethers } from "hardhat";
import { TypedDataDomain, Wallet } from "ethers";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

import { Signer as SignerHelper } from "../../../typechain-types/contracts/utils/Signer";

export async function getEIP712Domain(
  contract: string,
  wallet?: HardhatEthersSigner | Wallet,
): Promise<TypedDataDomain> {
  const signerHelper: SignerHelper = await ethers.getContractAt(
    "Signer",
    contract,
    wallet,
  );

  const { name, version, chainId, verifyingContract } =
    await signerHelper.eip712Domain();
  const domain: TypedDataDomain = {
    name: name,
    version: version,
    chainId: chainId,
    verifyingContract: verifyingContract,
  };

  return domain;
}
