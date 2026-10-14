import { useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { Eye, EyeOff, ShieldAlert, TriangleAlert } from 'lucide-react';
import { api, getToken, setToken } from '../api/client';
import type { LoginResponse } from '../api/types';

export function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (getToken() !== null) return <Navigate to="/" replace />;

  const submit = async (formEvent: FormEvent<HTMLFormElement>) => {
    formEvent.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.post<LoginResponse>('/auth/login', { username, password });
      setToken(result.access_token);
      navigate('/', { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
      setBusy(false);
    }
  };

  const inputClasses =
    'w-full rounded border border-edge bg-base px-3 py-2 font-mono text-sm text-ink outline-none transition-colors placeholder:text-dim/60 focus:border-lime/60';

  return (
    <div className="flex min-h-screen items-center justify-center bg-base bg-starfield p-4">
      <div className="panel w-full max-w-sm p-8">
        <div className="flex flex-col items-center text-center">
          <span className="flex h-10 w-10 items-center justify-center rounded bg-lime">
            <ShieldAlert className="h-5 w-5 text-[#0f1113]" strokeWidth={2.5} />
          </span>
          <h1 className="mt-4 font-mono text-[15px] font-semibold tracking-tight text-ink">
            Attack<span className="text-lime">Observatory</span>
          </h1>
          <p className="mt-1 font-mono text-[10px] uppercase tracking-[2px] text-dim">intel console</p>
        </div>

        <form onSubmit={submit} className="mt-8 space-y-4">
          <div>
            <label
              htmlFor="username"
              className="mb-1.5 block font-mono text-[10px] font-medium uppercase tracking-[0.6px] text-dim"
            >
              username
            </label>
            <input
              id="username"
              type="text"
              autoComplete="username"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className={inputClasses}
              placeholder="admin"
            />
          </div>
          <div>
            <label
              htmlFor="password"
              className="mb-1.5 block font-mono text-[10px] font-medium uppercase tracking-[0.6px] text-dim"
            >
              password
            </label>
            <div className="relative">
              <input
                id="password"
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className={`${inputClasses} pr-10`}
                placeholder="••••••••"
              />
              <button
                type="button"
                onClick={() => setShowPassword((value) => !value)}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-dim transition-colors hover:text-ink"
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>

          {error !== null && (
            <p className="flex items-center gap-2 rounded border border-neg/30 bg-neg/10 px-3 py-2 font-mono text-[11px] text-neg">
              <TriangleAlert className="h-3.5 w-3.5 shrink-0" />
              {error}
            </p>
          )}

          <SubmitButton busy={busy} enabled={username !== '' && password !== ''} />
        </form>
      </div>
    </div>
  );
}

function SubmitButton({ busy, enabled }: { busy: boolean; enabled: boolean }): ReactNode {
  return (
    <button
      type="submit"
      disabled={busy || !enabled}
      className="w-full rounded bg-lime px-4 py-2 font-mono text-[13px] font-semibold uppercase tracking-[0.6px] text-[#0f1113] transition-colors hover:bg-lime/85 disabled:cursor-not-allowed disabled:opacity-40"
    >
      {busy ? 'authenticating…' : 'sign in'}
    </button>
  );
}
