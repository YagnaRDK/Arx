/**
 * Just enough RLP to know when a streamed transaction payload is complete, and
 * to read a legacy transaction's chain id.
 *
 * The device needs this because it is fed the transaction in chunks and has to
 * decide, without being told, when it has all of it. RLP makes that decidable:
 * a list header declares the total length of its contents, so the expected
 * frame size is known from the first few bytes.
 */

export type RlpListHeader = {
  /** Bytes occupied by the header itself. */
  headerLength: number;
  /** Bytes of list contents the header declares. */
  payloadLength: number;
  /** headerLength + payloadLength. */
  totalLength: number;
};

/**
 * Reads a list header. Returns null when not enough bytes have arrived yet to
 * determine the length — which is "keep streaming", not an error.
 */
export function readRlpListHeader(data: Uint8Array): RlpListHeader | null {
  if (data.length < 1) {
    return null;
  }

  const prefix = data[0]!;

  if (prefix >= 0xc0 && prefix <= 0xf7) {
    const payloadLength = prefix - 0xc0;
    return { headerLength: 1, payloadLength, totalLength: 1 + payloadLength };
  }

  if (prefix >= 0xf8) {
    const lengthOfLength = prefix - 0xf7;

    if (data.length < 1 + lengthOfLength) {
      return null;
    }

    let payloadLength = 0;

    for (let i = 0; i < lengthOfLength; i += 1) {
      payloadLength = payloadLength * 256 + data[1 + i]!;
    }

    return {
      headerLength: 1 + lengthOfLength,
      payloadLength,
      totalLength: 1 + lengthOfLength + payloadLength,
    };
  }

  // Not a list. A transaction payload is always a list (or a type byte followed
  // by one), so this is malformed rather than incomplete.
  return null;
}

export type RlpItem = { start: number; length: number };

/**
 * Walks the top-level items of an RLP list, returning each one's byte range.
 * Returns null if the data is truncated or not a list.
 */
export function readRlpListItems(data: Uint8Array): RlpItem[] | null {
  const header = readRlpListHeader(data);

  if (!header || data.length < header.totalLength) {
    return null;
  }

  const items: RlpItem[] = [];
  let offset = header.headerLength;
  const end = header.totalLength;

  while (offset < end) {
    const prefix = data[offset]!;

    if (prefix <= 0x7f) {
      items.push({ start: offset, length: 1 });
      offset += 1;
    } else if (prefix <= 0xb7) {
      const length = prefix - 0x80;
      items.push({ start: offset + 1, length });
      offset += 1 + length;
    } else if (prefix <= 0xbf) {
      const lengthOfLength = prefix - 0xb7;
      let length = 0;

      for (let i = 0; i < lengthOfLength; i += 1) {
        length = length * 256 + data[offset + 1 + i]!;
      }

      items.push({ start: offset + 1 + lengthOfLength, length });
      offset += 1 + lengthOfLength + length;
    } else {
      // A nested list. Recorded as an opaque span — no transaction field this
      // code reads is itself a list.
      const nested = readRlpListHeader(data.subarray(offset));

      if (!nested) {
        return null;
      }

      items.push({ start: offset, length: nested.totalLength });
      offset += nested.totalLength;
    }

    if (offset > end) {
      return null;
    }
  }

  return items;
}

/** Reads an RLP item's bytes as a big-endian unsigned integer. */
export function rlpItemToBigInt(data: Uint8Array, item: RlpItem): bigint {
  let value = 0n;

  for (let i = 0; i < item.length; i += 1) {
    value = (value << 8n) | BigInt(data[item.start + i]!);
  }

  return value;
}
