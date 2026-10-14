/**
 * Live event stream over /api/v1/ws/live?token=<jwt>.
 * Auto-reconnects with exponential backoff (1s → 2s → 4s … capped at 30s)
 * and keeps the connection warm with ping frames.
 */

import { useEffect, useRef, useState } from 'react';
import { clearToken, getToken } from './client';
import type { Event } from './types';

export type WsStatus = 'connecting' | 'open' | 'reconnecting' | 'closed';

const MAX_BACKOFF_MS = 30_000;
const PING_INTERVAL_MS = 25_000;

export interface LiveFeedOptions {
  /** Maximum number of events kept in the client-side buffer (newest first). */
  max?: number;
  /** Optional side-channel callback fired for every incoming event. */
  onEvent?: (event: Event) => void;
}

export interface LiveFeedResult {
  events: Event[];
  status: WsStatus;
  /** Consecutive failed connection attempts (0 while connected). */
  attempt: number;
}

export function useLiveFeed({ max = 100, onEvent }: LiveFeedOptions = {}): LiveFeedResult {
  const [events, setEvents] = useState<Event[]>([]);
  const [status, setStatus] = useState<WsStatus>('connecting');
  const [attempt, setAttempt] = useState(0);

  const onEventRef = useRef(onEvent);
  useEffect(() => {
    onEventRef.current = onEvent;
  }, [onEvent]);

  useEffect(() => {
    let disposed = false;
    let socket: WebSocket | null = null;
    let pingTimer: number | undefined;
    let reconnectTimer: number | undefined;
    let attempts = 0;

    const connect = (): void => {
      const token = getToken();
      if (disposed || !token) {
        setStatus('closed');
        return;
      }
      setStatus(attempts === 0 ? 'connecting' : 'reconnecting');
      setAttempt(attempts);

      const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
      socket = new WebSocket(
        `${protocol}${window.location.host}/api/v1/ws/live?token=${encodeURIComponent(token)}`,
      );

      socket.onopen = () => {
        attempts = 0;
        setAttempt(0);
        setStatus('open');
        pingTimer = window.setInterval(() => {
          if (socket?.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify({ type: 'ping' }));
          }
        }, PING_INTERVAL_MS);
      };

      socket.onmessage = (message: MessageEvent<string>) => {
        let data: unknown;
        try {
          data = JSON.parse(message.data);
        } catch {
          // Malformed frame; ignore it.
          return;
        }
        if (typeof data !== 'object' || data === null) return;
        if ('type' in data && (data as { type: unknown }).type === 'pong') return;
        if (!('attack_type' in data)) return;
        const event = data as Event;
        setEvents((prev) => {
          const next = [event, ...prev];
          return next.length > max ? next.slice(0, max) : next;
        });
        onEventRef.current?.(event);
      };

      socket.onclose = (ev: CloseEvent) => {
        window.clearInterval(pingTimer);
        // Server closes 4401 when the JWT is missing/expired: the session is
        // gone, so drop it and go sign in again instead of retrying forever.
        if (ev.code === 4401 && !disposed) {
          clearToken();
          window.location.assign('/login');
          setStatus('closed');
          return;
        }
        if (disposed) {
          setStatus('closed');
          return;
        }
        attempts += 1;
        setAttempt(attempts);
        setStatus('reconnecting');
        const delay = Math.min(1000 * 2 ** (attempts - 1), MAX_BACKOFF_MS);
        reconnectTimer = window.setTimeout(connect, delay);
      };

      socket.onerror = () => {
        socket?.close();
      };
    };

    connect();

    return () => {
      disposed = true;
      window.clearInterval(pingTimer);
      window.clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, [max]);

  return { events, status, attempt };
}
