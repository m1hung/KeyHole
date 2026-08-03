/**
 * Have I Been Pwned range lookup — surface-side fetch.
 *
 * Core hashes and matches; this module is the only place a client talks to
 * api.pwnedpasswords.com. Callers must gate on `settings.breachCheckEnabled`
 * and never invoke this from unlock, timers, or autofill.
 */

import { countFromRangeResponse, hashForRangeQuery } from '@keyhole/core';

const RANGE_URL = 'https://api.pwnedpasswords.com/range';

export async function checkPasswordBreachCount(password: string): Promise<number> {
  const { prefix, suffix } = await hashForRangeQuery(password);
  const response = await fetch(`${RANGE_URL}/${prefix}`, {
    headers: {
      // Pads the response so its size does not leak how many suffixes matched.
      'Add-Padding': 'true',
    },
  });
  if (!response.ok) {
    throw new Error(`Have I Been Pwned returned HTTP ${response.status}.`);
  }
  return countFromRangeResponse(await response.text(), suffix);
}
