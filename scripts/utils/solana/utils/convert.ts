export function toBytes32Array(value: bigint): number[] {
  // Convert to hex, pad to 64 chars (32 bytes) and remove 0x
  const hex = value.toString(16).padStart(64, "0");

  return Array.from(Buffer.from(hex, "hex"));
}
