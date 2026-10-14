import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import type { ReactElement } from 'react';
import { getToken } from './api/client';
import { Layout } from './components/Layout';
import { Login } from './pages/Login';
import { Overview } from './pages/Overview';
import { LiveFeed } from './pages/LiveFeed';
import { AttackMap } from './pages/AttackMap';
import { SshAnalytics } from './pages/SshAnalytics';
import { WebAnalytics } from './pages/WebAnalytics';
import { CredentialAnalytics } from './pages/CredentialAnalytics';
import { NetworkAnalytics } from './pages/NetworkAnalytics';
import { IocCenter } from './pages/IocCenter';

function RequireAuth({ children }: { children: ReactElement }): ReactElement {
  if (getToken() === null) return <Navigate to="/login" replace />;
  return children;
}

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          element={
            <RequireAuth>
              <Layout />
            </RequireAuth>
          }
        >
          <Route path="/" element={<Overview />} />
          <Route path="/live" element={<LiveFeed />} />
          <Route path="/map" element={<AttackMap />} />
          <Route path="/ssh" element={<SshAnalytics />} />
          <Route path="/web" element={<WebAnalytics />} />
          <Route path="/credentials" element={<CredentialAnalytics />} />
          <Route path="/network" element={<NetworkAnalytics />} />
          <Route path="/ioc" element={<IocCenter />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
