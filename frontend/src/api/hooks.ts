/** Small data-fetching hook on top of the API client. */

import { useEffect, useState } from 'react';
import { api } from './client';
import { withQuery } from './client';
import type { QueryParams } from './client';

export interface UseApiResult<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

export function useApi<T>(
  path: string,
  params?: QueryParams,
): UseApiResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);

  // Serialized once per render; stable string identity drives the effect.
  const fullPath = withQuery(path, params);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api
      .get<T>(fullPath)
      .then((result) => {
        if (!cancelled) {
          setData(result);
          setError(null);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Request failed');
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [fullPath, tick]);

  return { data, error, loading, reload: () => setTick((t) => t + 1) };
}
