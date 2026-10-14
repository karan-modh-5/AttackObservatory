import { useEffect, useRef } from 'react';
import type { MutableRefObject } from 'react';
import type { MapPoint } from '../api/types';
import landDots from '../lib/land-dots.json';

/** Temporary bright ping rendered for a live websocket event. */
export interface GlobePulse {
  id: number;
  lat: number;
  lon: number;
  /** Epoch ms when the pulse was observed; fades out over PULSE_MS. */
  at: number;
}

export const PULSE_MS = 2600;

interface GlobeHighlight {
  label: string;
  lat: number;
  lon: number;
}

interface GlobeCanvasProps {
  points: MapPoint[];
  /** Top origins drawn with a "CN 8.9%" style chip. */
  highlights: GlobeHighlight[];
  /** Label rendered on the sensor marker chip. */
  sensorLabel: string;
  /** Live pulses pushed by the websocket feed; the canvas prunes expired ones. */
  pulsesRef: MutableRefObject<GlobePulse[]>;
  className?: string;
}

const DEG = Math.PI / 180;
const AUTO_ROTATE = 0.0007; // rad per frame — slow drift (full turn ≈ 2.5 min)
const DRAG_SENSITIVITY = 0.005;
const MIN_ZOOM = 0.7;
const MAX_ZOOM = 2.6;

const LIME = '#d1fe17';
const GREEN = '#40d986';
const RED = '#ff5449';

/** Precomputed land dot cloud: cos/sin of latitude + raw longitude radians. */
const LAND = (() => {
  const raw = landDots.points as number[];
  const dots: Array<{ cosLat: number; sinLat: number; lonRad: number }> = [];
  for (let i = 0; i < raw.length; i += 2) {
    const latRad = (raw[i] * Math.PI) / 180;
    dots.push({ cosLat: Math.cos(latRad), sinLat: Math.sin(latRad), lonRad: (raw[i + 1] * Math.PI) / 180 });
  }
  return dots;
})();

/** Deterministic starfield in canvas fractions (fx, fy) + twinkle phase. */
const STARS = (() => {
  let seed = 1337;
  const rand = (): number => {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed / 0x100000000;
  };
  const stars: Array<{ fx: number; fy: number; size: number; alpha: number; phase: number }> = [];
  for (let i = 0; i < 170; i++) {
    stars.push({ fx: rand(), fy: rand(), size: rand() < 0.85 ? 1 : 1.8, alpha: 0.14 + rand() * 0.38, phase: rand() * Math.PI * 2 });
  }
  return stars;
})();

/** Great-circle interpolation between two lat/lon points. */
function slerpPath(
  lat1: number, lon1: number, lat2: number, lon2: number, segments: number,
): Array<{ lat: number; lon: number; m: number }> {
  const toVec = (lat: number, lon: number): [number, number, number] => {
    const latRad = (lat * Math.PI) / 180;
    const lonRad = (lon * Math.PI) / 180;
    return [Math.cos(latRad) * Math.cos(lonRad), Math.cos(latRad) * Math.sin(lonRad), Math.sin(latRad)];
  };
  const a = toVec(lat1, lon1);
  const b = toVec(lat2, lon2);
  const dot = Math.min(1, Math.max(-1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]));
  const omega = Math.acos(dot);
  const sinOmega = Math.sin(omega);
  // Barely lift off the surface: arcs must read as painted on the globe and
  // wrap with the rotation, not float into space (reference behavior).
  const arcHeight = 0.015 + 0.03 * (omega / Math.PI);
  const path: Array<{ lat: number; lon: number; m: number }> = [];
  for (let i = 0; i <= segments; i++) {
    const t = i / segments;
    let x: number, y: number, z: number;
    if (sinOmega < 1e-6) {
      x = a[0]; y = a[1]; z = a[2];
    } else {
      const wa = Math.sin((1 - t) * omega) / sinOmega;
      const wb = Math.sin(t * omega) / sinOmega;
      x = wa * a[0] + wb * b[0];
      y = wa * a[1] + wb * b[1];
      z = wa * a[2] + wb * b[2];
    }
    path.push({
      lat: (Math.asin(Math.max(-1, Math.min(1, z))) * 180) / Math.PI,
      lon: (Math.atan2(y, x) * 180) / Math.PI,
      m: 1 + arcHeight * Math.sin(Math.PI * t),
    });
  }
  return path;
}

/**
 * Dependency-free orthographic globe on a 2D canvas: dark shaded sphere,
 * graticule, attacker dots, bezier attack arcs into the sensor, live pulses.
 * x = R·cos(lat)·sin(lon−rot), y = R·sin(lat); a point is on the visible
 * hemisphere when cos(lat)·cos(lon−rot) > 0.
 */
export function GlobeCanvas({ points, highlights, sensorLabel, pulsesRef, className = '' }: GlobeCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const pointsRef = useRef(points);
  const highlightsRef = useRef(highlights);

  useEffect(() => {
    pointsRef.current = points;
  }, [points]);

  useEffect(() => {
    highlightsRef.current = highlights;
  }, [highlights]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (canvas === null) return;
    const ctx = canvas.getContext('2d');
    if (ctx === null) return;

    let width = canvas.clientWidth;
    let height = canvas.clientHeight;
    let dpr = window.devicePixelRatio || 1;
    let rot = -30 * DEG;
    let zoom = 1;
    let dragging = false;
    let lastX = 0;
    let frame = 0;

    const resize = (): void => {
      width = canvas.clientWidth;
      height = canvas.clientHeight;
      dpr = window.devicePixelRatio || 1;
      canvas.width = Math.max(1, Math.round(width * dpr));
      canvas.height = Math.max(1, Math.round(height * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();

    const observer = new ResizeObserver(resize);
    observer.observe(canvas);

    interface Projected {
      x: number;
      y: number;
      visible: boolean;
      depth: number;
    }

    const project = (lat: number, lon: number, cx: number, cy: number, radius: number): Projected => {
      const latRad = lat * DEG;
      const lonRad = lon * DEG;
      const cosLat = Math.cos(latRad);
      const depth = cosLat * Math.cos(lonRad - rot);
      return {
        x: cx + radius * cosLat * Math.sin(lonRad - rot),
        y: cy - radius * Math.sin(latRad),
        visible: depth > 0,
        depth,
      };
    };

    /** Chip with mono text, ShardLure panel styling. */
    const drawChip = (text: string, x: number, y: number, accent: string): void => {
      ctx.font = '500 9px "JetBrains Mono", monospace';
      const textWidth = ctx.measureText(text).width;
      const padX = 6;
      const boxW = textWidth + padX * 2 + 8;
      const boxH = 16;
      const bx = Math.min(Math.max(4, x), width - boxW - 4);
      const by = Math.min(Math.max(4, y), height - boxH - 4);
      ctx.fillStyle = 'rgba(15, 17, 19, 0.92)';
      ctx.strokeStyle = '#24272c';
      ctx.beginPath();
      ctx.roundRect(bx, by, boxW, boxH, 3);
      ctx.fill();
      ctx.stroke();
      ctx.fillStyle = accent;
      ctx.beginPath();
      ctx.arc(bx + padX + 1, by + boxH / 2, 2, 0, 2 * Math.PI);
      ctx.fill();
      ctx.fillStyle = '#f7f7f8';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'middle';
      ctx.fillText(text, bx + padX + 7, by + boxH / 2 + 0.5);
    };

    const draw = (now: number): void => {
      if (!dragging) rot -= AUTO_ROTATE;
      const cx = width / 2;
      const cy = height / 2;
      const radius = (Math.min(width, height) / 2 - 10) * zoom;

      ctx.clearRect(0, 0, width, height);

      // Starfield: static seeded stars, twinkling subtly, hidden behind the globe disc.
      for (const star of STARS) {
        const sx = star.fx * width;
        const sy = star.fy * height;
        const dx = sx - cx;
        const dy = sy - cy;
        if (dx * dx + dy * dy < (radius + 14) * (radius + 14)) continue;
        ctx.globalAlpha = star.alpha * (0.75 + 0.25 * Math.sin(now / 900 + star.phase));
        ctx.fillStyle = '#f7f7f8';
        ctx.fillRect(sx, sy, star.size, star.size);
      }
      ctx.globalAlpha = 1;

      // Sphere: dark radial shading, lighter toward the upper left.
      const shade = ctx.createRadialGradient(cx - radius * 0.35, cy - radius * 0.4, radius * 0.1, cx, cy, radius);
      shade.addColorStop(0, '#191c20');
      shade.addColorStop(0.7, '#101215');
      shade.addColorStop(1, '#0a0b0d');
      ctx.fillStyle = shade;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, 2 * Math.PI);
      ctx.fill();
      ctx.strokeStyle = 'rgba(36, 39, 44, 0.9)';
      ctx.lineWidth = 1;
      ctx.stroke();

      // Continents: halftone dot cloud, depth-faded — the dotted Earth look.
      ctx.fillStyle = '#f7f7f8';
      for (const dot of LAND) {
        const delta = dot.lonRad - rot;
        const cosDelta = Math.cos(delta);
        const depth = dot.cosLat * cosDelta;
        if (depth <= 0.03) continue;
        const x = cx + radius * dot.cosLat * Math.sin(delta);
        const y = cy - radius * dot.sinLat;
        ctx.globalAlpha = 0.07 + 0.16 * depth;
        ctx.fillRect(x, y, 1.5, 1.5);
      }
      ctx.globalAlpha = 1;

      // Graticule: meridians and parallels every 20°, front hemisphere only.
      ctx.strokeStyle = 'rgba(247, 247, 248, 0.035)';
      const strokePath = (samples: Array<[number, number]>): void => {
        ctx.beginPath();
        let pen = false;
        for (const [lat, lon] of samples) {
          const p = project(lat, lon, cx, cy, radius);
          if (p.visible) {
            if (pen) ctx.lineTo(p.x, p.y);
            else ctx.moveTo(p.x, p.y);
            pen = true;
          } else {
            pen = false;
          }
        }
        ctx.stroke();
      };
      for (let lon = -180; lon < 180; lon += 20) {
        const samples: Array<[number, number]> = [];
        for (let lat = -90; lat <= 90; lat += 5) samples.push([lat, lon]);
        strokePath(samples);
      }
      for (let lat = -60; lat <= 60; lat += 20) {
        const samples: Array<[number, number]> = [];
        for (let lon = -180; lon <= 180; lon += 5) samples.push([lat, lon]);
        strokePath(samples);
      }

      const sensorLat = 12.97;
      const sensorLon = 77.59;
      const sensor = project(sensorLat, sensorLon, cx, cy, radius);

      // Attack arcs: great-circle flights from each origin into the sensor,
      // with a comet pulse traveling each route (ShardLure-style live map).
      const current = pointsRef.current;
      const maxWeight = Math.max(1, ...current.map((point) => point.weight));
      const highlightKeys = new Set(
        highlightsRef.current.map((h) => `${h.lat.toFixed(2)}:${h.lon.toFixed(2)}`),
      );
      for (const point of current) {
        // Origin on the far side is fine: the route is drawn per-segment and
        // only its front-hemisphere portion is visible, so arcs appear to wrap
        // over the horizon toward the sensor (reference behavior).
        const sensorDim = sensor.visible ? 1 : 0.45;
        const hot = highlightKeys.has(`${point.lat.toFixed(2)}:${point.lon.toFixed(2)}`);
        const color = hot ? '255, 84, 73' : '209, 254, 23';
        const path = slerpPath(point.lat, point.lon, sensorLat, sensorLon, 30);

        // Faint full route (front segments only).
        ctx.strokeStyle = `rgba(${color}, ${0.28 * sensorDim})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        let pen = false;
        for (const node of path) {
          const p = project(node.lat, node.lon, cx, cy, radius * node.m);
          if (p.visible) {
            if (pen) ctx.lineTo(p.x, p.y);
            else ctx.moveTo(p.x, p.y);
            pen = true;
          } else {
            pen = false;
          }
        }
        ctx.stroke();

        // Comet: bright head + fading tail cycling origin -> sensor.
        const phase = ((point.lat + 360 - point.lon) % 10) / 10; // stable per origin
        const speed = 3400 + (point.weight % 7) * 260;
        const head = ((now / speed) + phase) % 1;
        for (let k = 0; k < 9; k++) {
          const t = head - k * 0.011;
          if (t < 0 || t > 1) continue;
          const node = path[Math.round(t * 30)];
          const p = project(node.lat, node.lon, cx, cy, radius * node.m);
          if (!p.visible) continue;
          const fade = (1 - k / 9) * (1 - Math.abs(head - 0.5) * 0.4) * sensorDim;
          ctx.globalAlpha = Math.max(0.06, fade * (k === 0 ? 1 : 0.5));
          ctx.fillStyle = hot ? RED : LIME;
          const r = k === 0 ? 2.2 : 1.3;
          ctx.beginPath();
          ctx.arc(p.x, p.y, r, 0, 2 * Math.PI);
          ctx.fill();
        }
        ctx.globalAlpha = 1;
      }

      // Attacker dots, depth-faded; the highlighted origins sit on top in red.
      for (const point of current) {
        const p = project(point.lat, point.lon, cx, cy, radius);
        if (!p.visible) continue;
        const hot = highlightKeys.has(`${point.lat.toFixed(2)}:${point.lon.toFixed(2)}`);
        const r = hot ? 3.5 : 1.2 + 2.2 * (point.weight / maxWeight);
        ctx.globalAlpha = 0.3 + 0.7 * p.depth;
        ctx.fillStyle = hot ? RED : GREEN;
        ctx.beginPath();
        ctx.arc(p.x, p.y, r, 0, 2 * Math.PI);
        ctx.fill();
        ctx.globalAlpha = 1;
      }

      // Live pulses: bright core plus an expanding fading ring.
      const pulses = pulsesRef.current;
      const alive: GlobePulse[] = [];
      for (const pulse of pulses) {
        const age = now - pulse.at;
        if (age < 0 || age > PULSE_MS) continue;
        alive.push(pulse);
        const p = project(pulse.lat, pulse.lon, cx, cy, radius);
        if (!p.visible) continue;
        const t = age / PULSE_MS;
        ctx.globalAlpha = (1 - t) * 0.85;
        ctx.strokeStyle = LIME;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(p.x, p.y, 3 + 16 * t, 0, 2 * Math.PI);
        ctx.stroke();
        ctx.fillStyle = LIME;
        ctx.beginPath();
        ctx.arc(p.x, p.y, 2.5, 0, 2 * Math.PI);
        ctx.fill();
        ctx.globalAlpha = 1;
      }
      if (alive.length !== pulses.length) pulsesRef.current = alive;

      // Sensor marker + chip.
      if (sensor.visible) {
        ctx.fillStyle = LIME;
        ctx.beginPath();
        ctx.arc(sensor.x, sensor.y, 4.5, 0, 2 * Math.PI);
        ctx.fill();
        ctx.strokeStyle = 'rgba(209, 254, 23, 0.35)';
        ctx.lineWidth = 6;
        ctx.beginPath();
        ctx.arc(sensor.x, sensor.y, 8, 0, 2 * Math.PI);
        ctx.stroke();
        drawChip(sensorLabel, sensor.x + 12, sensor.y - 8, LIME);
      }

      // Top-origin chips ("CN 8.9%").
      for (const h of highlightsRef.current) {
        const p = project(h.lat, h.lon, cx, cy, radius);
        if (!p.visible) continue;
        drawChip(h.label, p.x + 10, p.y - 22, RED);
      }

      frame = requestAnimationFrame(draw);
    };

    frame = requestAnimationFrame(draw);

    const onPointerDown = (event: PointerEvent): void => {
      dragging = true;
      lastX = event.clientX;
      canvas.setPointerCapture(event.pointerId);
    };
    const onPointerMove = (event: PointerEvent): void => {
      if (!dragging) return;
      // x = R·cos(lat)·sin(lon − rot): increasing rot moves surface points
      // LEFT, so dragging right must DECREASE rot for the surface to follow
      // the cursor.
      rot -= (event.clientX - lastX) * DRAG_SENSITIVITY;
      lastX = event.clientX;
    };
    const onPointerUp = (event: PointerEvent): void => {
      dragging = false;
      if (canvas.hasPointerCapture(event.pointerId)) canvas.releasePointerCapture(event.pointerId);
    };
    const onWheel = (event: WheelEvent): void => {
      event.preventDefault();
      zoom = zoom * (event.deltaY < 0 ? 1.08 : 0.926);
      zoom = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, zoom));
    };

    canvas.addEventListener('pointerdown', onPointerDown);
    canvas.addEventListener('pointermove', onPointerMove);
    canvas.addEventListener('pointerup', onPointerUp);
    canvas.addEventListener('pointercancel', onPointerUp);
    canvas.addEventListener('wheel', onWheel, { passive: false });

    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      canvas.removeEventListener('pointerdown', onPointerDown);
      canvas.removeEventListener('pointermove', onPointerMove);
      canvas.removeEventListener('pointerup', onPointerUp);
      canvas.removeEventListener('pointercancel', onPointerUp);
      canvas.removeEventListener('wheel', onWheel);
    };
  }, [pulsesRef, sensorLabel]);

  return <canvas ref={canvasRef} className={`h-full w-full cursor-grab touch-none active:cursor-grabbing ${className}`} />;
}
