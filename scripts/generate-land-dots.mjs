#!/usr/bin/env node
/**
 * Rasterize Natural Earth 110m land polygons into a halftone dot cloud for the
 * globe renderer. Output: frontend/src/lib/land-dots.json
 *   { "step": 1.7, "points": [lat, lon, lat, lon, ...] }
 *
 * Usage: node scripts/generate-land-dots.mjs [path/to/ne_110m_land.geojson]
 * Source: https://github.com/nvkelso/natural-earth-vector (public domain).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const src = process.argv[2] ?? join(here, '..', 'land110.geojson');
const out = join(here, '..', 'frontend', 'src', 'lib', 'land-dots.json');
const STEP = 1.7; // degrees between dot rows

const geo = JSON.parse(readFileSync(src, 'utf8'));

/** Collect outer rings per polygon; holes are ignored at 110m dot scale. */
const polygons = [];
for (const feature of geo.features) {
  const g = feature.geometry;
  if (g.type === 'Polygon') polygons.push(g.coordinates[0]);
  else if (g.type === 'MultiPolygon') for (const poly of g.coordinates) polygons.push(poly[0]);
}

/** Ray casting; ring is an array of [lon, lat]. */
function inside(lon, lat, ring) {
  let hit = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const [xi, yi] = ring[i];
    const [xj, yj] = ring[j];
    if (yi > lat !== yj > lat && lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi) hit = !hit;
  }
  return hit;
}

const points = [];
for (let lat = -78; lat <= 84; lat += STEP) {
  // Widen the longitude step toward the poles so surface dot density stays even.
  const lonStep = STEP / Math.max(0.25, Math.cos((lat * Math.PI) / 180));
  for (let lon = -180; lon < 180; lon += lonStep) {
    for (const ring of polygons) {
      if (inside(lon, lat, ring)) {
        points.push(Number(lat.toFixed(2)), Number(lon.toFixed(2)));
        break;
      }
    }
  }
}

writeFileSync(out, JSON.stringify({ step: STEP, points }));
console.log(`land dots: ${points.length / 2} -> ${out}`);
