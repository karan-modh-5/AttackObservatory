import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  Activity,
  AppWindow,
  Crosshair,
  Globe,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Network,
  ShieldAlert,
  Terminal,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { api, clearToken } from '../api/client';
import type { MeResponse } from '../api/types';
import { useLiveFeed } from '../api/ws';
import type { WsStatus } from '../api/ws';

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
}

const NAV: NavItem[] = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/live', label: 'Live Feed', icon: Activity },
  { to: '/map', label: 'Attack Map', icon: Globe },
  { to: '/ssh', label: 'SSH', icon: Terminal },
  { to: '/web', label: 'Web', icon: AppWindow },
  { to: '/credentials', label: 'Credentials', icon: KeyRound },
  { to: '/network', label: 'Network', icon: Network },
  { to: '/ioc', label: 'IOC Center', icon: Crosshair },
];

const STATUS_DOT: Record<WsStatus, string> = {
  open: 'bg-pos',
  connecting: 'bg-warn',
  reconnecting: 'bg-warn',
  closed: 'bg-neg',
};

const STATUS_LABEL: Record<WsStatus, string> = {
  open: 'live',
  connecting: 'connecting',
  reconnecting: 'retrying',
  closed: 'down',
};

function BrandMark(): ReactNode {
  return (
    <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded bg-lime">
      <ShieldAlert className="h-3.5 w-3.5 text-[#0f1113]" strokeWidth={2.5} />
    </span>
  );
}

export function Layout() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const { status } = useLiveFeed({ max: 1 });

  useEffect(() => {
    let cancelled = false;
    api
      .get<MeResponse>('/auth/me')
      .then((me) => {
        if (!cancelled) setUsername(me.username);
      })
      .catch(() => {
        // 401 is handled globally by the API client (redirect to /login).
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const logout = () => {
    clearToken();
    navigate('/login', { replace: true });
  };

  const renderNav = (onNavigate?: () => void): ReactNode => (
    <>
      {NAV.map((item) => {
        const Icon = item.icon;
        return (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            onClick={onNavigate}
            title={item.label}
            className={({ isActive }) =>
              `relative flex h-8 w-8 items-center justify-center rounded transition-colors ${
                isActive ? 'text-lime' : 'text-dim hover:text-ink'
              }`
            }
          >
            {({ isActive }) => (
              <>
                <Icon className="h-4 w-4" />
                {isActive && (
                  <span className="absolute -left-2 top-1/2 h-1 w-1 -translate-y-1/2 rounded-full bg-lime" />
                )}
              </>
            )}
          </NavLink>
        );
      })}
    </>
  );

  return (
    <div className="min-h-screen bg-base bg-starfield">
      {/* Narrow icon rail — desktop */}
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-11 flex-col items-center border-r border-edge bg-panel py-3 lg:flex">
        <NavLink to="/" title="AttackObservatory">
          <BrandMark />
        </NavLink>
        <nav className="mt-5 flex flex-1 flex-col items-center gap-1.5">{renderNav()}</nav>
        <button
          type="button"
          onClick={logout}
          title="Sign out"
          className="flex h-8 w-8 items-center justify-center rounded text-dim transition-colors hover:text-neg"
        >
          <LogOut className="h-4 w-4" />
        </button>
      </aside>

      <div className="lg:pl-11">
        {/* Top bar */}
        <header className="sticky top-0 z-30 flex h-12 items-center gap-3 border-b border-edge bg-panel px-4">
          <NavLink to="/" className="flex items-center gap-2.5">
            <span className="lg:hidden">
              <BrandMark />
            </span>
            <span className="h-1.5 w-1.5 rounded-full bg-lime" />
            <span className="font-mono text-[13px] font-semibold tracking-tight text-ink">
              Attack<span className="text-lime">Observatory</span>
            </span>
          </NavLink>
          <span className="hidden font-mono text-[10px] uppercase tracking-[2px] text-dim sm:inline">
            intel console
          </span>
          <div className="ml-auto flex items-center gap-3">
            <span
              className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.6px] text-dim"
              title={`websocket ${status}`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${STATUS_DOT[status]} ${
                  status === 'open' ? 'animate-pulse' : ''
                }`}
              />
              {STATUS_LABEL[status]}
            </span>
            {username !== '' && (
              <span className="hidden font-mono text-[10px] text-dim md:inline">{username}</span>
            )}
            <span className="hidden rounded border border-edge px-2 py-0.5 font-mono text-[9px] uppercase tracking-[0.6px] text-dim md:inline">
              density: comfortable
            </span>
            <button
              type="button"
              onClick={logout}
              className="rounded border border-edge p-1.5 text-dim transition-colors hover:text-neg lg:hidden"
              aria-label="Sign out"
            >
              <LogOut className="h-3.5 w-3.5" />
            </button>
          </div>
        </header>

        {/* Rail collapses to an icon row on small screens */}
        <nav className="flex items-center gap-1 overflow-x-auto border-b border-edge bg-panel px-3 py-1.5 lg:hidden">
          {renderNav()}
        </nav>

        <main className="p-4 lg:p-5">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
