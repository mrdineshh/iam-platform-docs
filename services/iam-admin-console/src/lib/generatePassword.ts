const UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const LOWER = "abcdefghijkmnpqrstuvwxyz";
const DIGIT = "23456789";
const SYMBOL = "!@#$%&*?";

function pick(chars: string, random: (max: number) => number): string {
  return chars[random(chars.length)];
}

function browserRandom(max: number): number {
  // Rejection sampling keeps every character equally likely.
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  do {
    crypto.getRandomValues(buf);
  } while (buf[0] >= limit);
  return buf[0] % max;
}

/**
 * A random temporary password that satisfies the usual rules (upper, lower, digit and symbol), with look-alike
 * characters (0/O, 1/l/I) left out so it can be read out or typed without mistakes.
 */
export function generatePassword(length = 14, random: (max: number) => number = browserRandom): string {
  const all = UPPER + LOWER + DIGIT + SYMBOL;
  const chars = [pick(UPPER, random), pick(LOWER, random), pick(DIGIT, random), pick(SYMBOL, random)];
  while (chars.length < length) chars.push(pick(all, random));
  // Fisher-Yates, so the guaranteed characters are not always first.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = random(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}
