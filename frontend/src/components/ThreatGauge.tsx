import { useEffect, useRef } from 'react';

/** Four 0-25 sub-scores that sum to the 0-100 threat score. */
export interface ThreatBreakdown {
  volume: number;
  intrusion: number;
  diversity: number;
  exposure: number;
}

const CAP = 25;

/**
 * Sub-scores from live telemetry: 24h volume (1 pt / 40 events), unique
 * attackers (1 pt / 20), attack-type diversity (3 pts per type) and country
 * exposure (1 pt / 6 countries), each capped at 25.
 */
export function breakdownFrom(
  stats: { last_24h: number; unique_attackers: number; countries: number } | null,
  attackTypeCount: number,
): ThreatBreakdown {
  return {
    volume: Math.min(CAP, Math.round((stats?.last_24h ?? 0) / 40)),
    intrusion: Math.min(CAP, Math.round((stats?.unique_attackers ?? 0) / 20)),
    diversity: Math.min(CAP, attackTypeCount * 3),
    exposure: Math.min(CAP, Math.round((stats?.countries ?? 0) / 6)),
  };
}

/** Sums the four capped sub-scores into the displayed 0-100 score. */
export function threatScore(parts: ThreatBreakdown): number {
  return Math.min(100, parts.volume + parts.intrusion + parts.diversity + parts.exposure);
}

export type ThreatLabel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/** 0-25 low, 26-50 medium, 51-75 high, 76-100 critical. */
export function threatLabel(score: number): ThreatLabel {
  if (score <= 25) return 'LOW';
  if (score <= 50) return 'MEDIUM';
  if (score <= 75) return 'HIGH';
  return 'CRITICAL';
}

export const THREAT_COLOR: Record<ThreatLabel, string> = {
  LOW: '#40d986',
  MEDIUM: '#d1fe17',
  HIGH: '#ffb454',
  CRITICAL: '#ff5449',
};

interface ThreatGaugeProps {
  score: number;
  /** Rendered width in px; height follows the semicircle ratio. */
  size?: number;
}

/** Canvas semicircle gauge with the score centered, ShardLure style. */
export function ThreatGauge({ score, size = 220 }: ThreatGaugeProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const label = threatLabel(score);
  const color = THREAT_COLOR[label];

  useEffect(() => {
    const canvas = canvasRef.current;
    if (canvas === null) return;
    const ctx = canvas.getContext('2d');
    if (ctx === null) return;

    const dpr = window.devicePixelRatio || 1;
    const w = size;
    const h = Math.round(size * 0.6);
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = `${w}px`;
    canvas.style.height = `${h}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    const cx = w / 2;
    const cy = h - 10;
    const r = Math.min(w / 2 - 16, h - 22);

    ctx.lineWidth = 9;
    ctx.lineCap = 'round';
    ctx.strokeStyle = '#24272c';
    ctx.beginPath();
    ctx.arc(cx, cy, r, Math.PI, 2 * Math.PI);
    ctx.stroke();

    const clamped = Math.max(0, Math.min(100, score));
    if (clamped > 0) {
      ctx.strokeStyle = color;
      ctx.beginPath();
      ctx.arc(cx, cy, r, Math.PI, Math.PI + Math.PI * (clamped / 100));
      ctx.stroke();
    }

    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = color;
    ctx.font = '600 26px "JetBrains Mono", monospace';
    ctx.fillText(String(Math.round(clamped)), cx, cy - r * 0.52);
    ctx.fillStyle = '#898a8b';
    ctx.font = '500 9px "JetBrains Mono", monospace';
    ctx.fillText(label, cx, cy - r * 0.52 + 22);
  }, [score, color, label, size]);

  return <canvas ref={canvasRef} aria-label={`Threat level ${label}, score ${Math.round(score)} of 100`} />;
}
