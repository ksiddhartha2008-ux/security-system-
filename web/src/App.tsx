import { useEffect } from 'react';
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { AuthProvider } from './lib/auth';
import { useToasts } from './lib/hooks';
import { ToastContext, ToastViewport } from './components/ui';
import { AppErrorBoundary } from './components/AppErrorBoundary';
import { AppShell, RequireAuth } from './components/layout';
import { LandingPage, LoginPage, NotFoundPage, PrivacyPage, SignupPage, TermsPage } from './pages/Public';
import OverviewPage from './pages/Overview';
import MonitoringPage from './pages/Monitoring';
import AssetsPage from './pages/Assets';
import { IncidentDetailPage, IncidentsPage } from './pages/Incidents';
import { InvestigationDetailPage, InvestigationsPage } from './pages/Investigations';
import IntelPage from './pages/Intel';
import DetectionsPage from './pages/Detections';
import PhishingPage from './pages/Phishing';
import VulnerabilitiesPage from './pages/Vulnerabilities';
import NetworkPage from './pages/Network';
import ForensicsPage from './pages/Forensics';
import AutomationPage from './pages/Automation';
import ReportsPage from './pages/Reports';
import SimulationsPage from './pages/Simulations';
import SimulationDetailPage from './pages/SimulationDetail';
import SettingsPage from './pages/Settings';
import PeoplePage from './pages/People';

function ScrollToTop() {
  const { pathname } = useLocation();
  useEffect(() => { window.scrollTo({ top: 0, behavior: 'instant' as ScrollBehavior }); }, [pathname]);
  return null;
}

export default function App() {
  const toasts = useToasts();
  return (
    <ToastContext.Provider value={{ push: toasts.push }}>
      <AppErrorBoundary>
      <BrowserRouter>
        <ScrollToTop />
        <AuthProvider>
          <Routes>
            <Route path="/" element={<LandingPage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/signup" element={<SignupPage />} />
            <Route path="/privacy" element={<PrivacyPage />} />
            <Route path="/terms" element={<TermsPage />} />
            <Route path="/app" element={<Navigate to="/overview" replace />} />

            <Route element={<RequireAuth><AppShell /></RequireAuth>}>
              <Route path="/overview" element={<OverviewPage />} />
              <Route path="/monitoring" element={<MonitoringPage />} />
              <Route path="/assets" element={<AssetsPage />} />
              <Route path="/incidents" element={<IncidentsPage />} />
              <Route path="/incidents/:id" element={<IncidentDetailPage />} />
              <Route path="/investigations" element={<InvestigationsPage />} />
              <Route path="/investigations/:id" element={<InvestigationDetailPage />} />
              <Route path="/threat-intel" element={<IntelPage />} />
              <Route path="/detections" element={<DetectionsPage />} />
              <Route path="/phishing" element={<PhishingPage />} />
              <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
              <Route path="/network" element={<NetworkPage />} />
              <Route path="/forensics" element={<ForensicsPage />} />
              <Route path="/automation" element={<AutomationPage />} />
              <Route path="/reports" element={<ReportsPage />} />
              <Route path="/simulations" element={<SimulationsPage />} />
              <Route path="/simulations/:id" element={<SimulationDetailPage />} />
              <Route path="/users" element={<PeoplePage />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Route>

            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </AuthProvider>
      </BrowserRouter>
      </AppErrorBoundary>
      <ToastViewport toasts={toasts.toasts} onDismiss={toasts.dismiss} />
    </ToastContext.Provider>
  );
}

