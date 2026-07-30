import { describe, expect, it } from 'vitest';
import { countFromRangeResponse, hashForRangeQuery } from '../src/breach.ts';

describe('hashForRangeQuery', () => {
  it('splits a SHA-1 digest into a 5-char prefix and 35-char suffix', async () => {
    // Known SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    const { prefix, suffix } = await hashForRangeQuery('password');
    expect(prefix).toBe('5BAA6');
    expect(suffix).toBe('1E4C9B93F3F0682250B6CF8331B7EE68FD8');
    expect(prefix).toHaveLength(5);
    expect(suffix).toHaveLength(35);
  });
});

describe('countFromRangeResponse', () => {
  const body = [
    '0018A45C4D1DEF81644B54AB7F969B88D65:1',
    '1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493',
    '00D4F6E8DA3F211726AA4D1F4656FA666B0:2',
  ].join('\n');

  it('returns the count for a matching suffix', () => {
    expect(countFromRangeResponse(body, '1E4C9B93F3F0682250B6CF8331B7EE68FD8')).toBe(3861493);
  });

  it('is case-insensitive on the suffix', () => {
    expect(countFromRangeResponse(body, '1e4c9b93f3f0682250b6cf8331b7ee68fd8')).toBe(3861493);
  });

  it('returns zero when the suffix is absent', () => {
    expect(countFromRangeResponse(body, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')).toBe(0);
  });
});
