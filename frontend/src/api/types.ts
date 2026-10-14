/**
 * TypeScript interfaces mirroring the API contract exactly
 * (docs/ARCHITECTURE.md §2 classification labels, §4 response models).
 */

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type Honeypot = 'cowrie' | 'snare' | 'tanner' | 'heralding' | 'suricata';

export type Service =
  | 'ssh'
  | 'telnet'
  | 'http'
  | 'https'
  | 'ftp'
  | 'smtp'
  | 'imap'
  | 'pop3'
  | 'scan';

export type AttackType =
  | 'SSH Brute Force'
  | 'Credential Stuffing'
  | 'Masscan'
  | 'Nmap'
  | 'Mirai'
  | 'Directory Scanning'
  | 'Web Scanning'
  | 'SQL Injection'
  | 'LFI'
  | 'RFI'
  | 'Malware Download'
  | 'Generic Bot Activity';

/** Normalized event (§1 schema + §4 WS frame). */
export interface Event {
  id: number;
  timestamp: string;
  source_ip: string | null;
  country: string | null;
  city: string | null;
  asn: string | null;
  lat: number | null;
  lon: number | null;
  honeypot: Honeypot;
  service: Service;
  attack_type: AttackType;
  username: string | null;
  password: string | null;
  payload: string | null;
  severity: Severity;
  session_id: string | null;
  /** Cowrie event classification on live WS frames (and newer REST rows). */
  event_kind?: 'connect' | 'client_version' | 'failed_password' | 'accepted' | 'command' | 'file_download' | 'file_upload' | null;
}

/** GET /events */
export interface EventsResponse {
  total: number;
  items: Event[];
}

/** GET /stats/overview */
export interface OverviewStats {
  total_attacks: number;
  unique_attackers: number;
  countries: number;
  credentials_captured: number;
  commands_executed: number;
  last_24h: number;
  ssh_events: number;
  ssh_unique_ips: number;
}

export interface TimeseriesPoint {
  bucket: string;
  total: number;
}

export interface AttackTypeCount {
  attack_type: string;
  count: number;
}

/** GET /stats/timeseries */
export interface Timeseries {
  interval: 'hour' | 'day';
  points: TimeseriesPoint[];
  by_type: AttackTypeCount[];
}

export interface NameCount {
  name: string;
  count: number;
}

/** GET /ssh/stats */
export interface SshStats {
  sessions: number;
  brute_force_events: number;
  credentials: number;
  commands: number;
  top_usernames: NameCount[];
  top_passwords: NameCount[];
  top_commands: NameCount[];
  malware_downloads: NameCount[];
  top_sources: NameCount[];
  /** All-time cowrie event-kind counts. */
  event_kinds: NameCount[];
}

/** GET /ssh/heatmap?hours=N */
export interface HeatmapResponse {
  /** ISO timestamps, ascending, one per column. */
  hours: string[];
  kinds: string[];
  /** matrix[kindIndex][hourIndex] event counts. */
  matrix: number[][];
}

/** GET /ssh/actors — one tracked attacker. */
export interface ActorRow {
  ip: string;
  country: string | null;
  city: string | null;
  playbook: string | null;
  intent: string | null;
  events: number;
  probes: number;
  last_cmd: string | null;
  last_seen: string;
}

/** GET /ssh/actors?days=N */
export interface ActorsResponse {
  actors: ActorRow[];
  playbooks: NameCount[];
  intents: NameCount[];
  event_kinds: NameCount[];
  sources: NameCount[];
  geography: NameCount[];
}

/** GET /ssh/payloads */
export interface PayloadStats {
  tracked_urls: number;
  saved: number;
  fetching_now: number;
  bytes_on_disk: number;
}

export interface PayloadItem {
  time: string;
  url: string;
  sha256: string;
  size_bytes: number;
  source_ip: string | null;
  origin: string;
}

export interface PayloadsResponse {
  stats: PayloadStats;
  items: PayloadItem[];
}

/** GET /web/stats */
export interface WebStats {
  scanner_events: number;
  top_urls: NameCount[];
  top_user_agents: NameCount[];
  exploit_payloads: NameCount[];
  attack_types: AttackTypeCount[];
}

export interface CredentialReusePair {
  username: string;
  password: string;
  count: number;
}

/** GET /credentials/stats */
export interface CredentialStats {
  unique_pairs: number;
  by_service: NameCount[];
  top_usernames: NameCount[];
  top_passwords: NameCount[];
  reuse_pairs: CredentialReusePair[];
}

export interface NetworkSource {
  name: string;
  country: string | null;
  count: number;
}

/** GET /network/stats */
export interface NetworkStats {
  total_alerts: number;
  signatures: NameCount[];
  protocols: NameCount[];
  top_sources: NetworkSource[];
}

export interface MapPoint {
  lat: number;
  lon: number;
  weight: number;
  country: string | null;
}

export interface CountryCount {
  name: string;
  count: number;
}

/** GET /map/points */
export interface MapPoints {
  points: MapPoint[];
  top_countries: CountryCount[];
}

export interface IocEntry {
  value: string;
  country?: string | null;
  asn?: string | null;
  hits: number;
  last_seen?: string | null;
}

/** GET /ioc */
export interface IocData {
  ips: IocEntry[];
  urls: IocEntry[];
  domains: IocEntry[];
  hashes: IocEntry[];
}

/** POST /auth/login */
export interface LoginResponse {
  access_token: string;
  token_type: string;
}

/** GET /auth/me */
export interface MeResponse {
  username: string;
}

/** GET /health */
export interface HealthResponse {
  status: string;
}

/** GET /health/ready */
export interface ReadinessResponse {
  status: string;
  database: string;
  geoip: string;
  queue_depth: number;
  uptime_seconds: number;
}
