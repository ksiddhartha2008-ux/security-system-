import { Suspense, lazy, useEffect } from 'react';
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { AuthProvider } from './lib/auth';
import { AstryxProviders } from './lib/theme/AstryxProviders';
import { ThemeModeProvider } from './lib/theme/ThemeMode';
import { useToasts } from './lib/hooks';
import { ToastContext, ToastViewport } from './components/ui';
import { AppErrorBoundary } from './components/AppErrorBoundary';
import { AppShellLayout, RequireAuth } from './components/layout';

const LandingPage = lazy(() => import('./pages/Public').then((module) => ({ default: module.LandingPage })));
const LoginPage = lazy(() => import('./pages/Public').then((module) => ({ default: module.LoginPage })));
const SignupPage = lazy(() => import('./pages/Public').then((module) => ({ default: module.SignupPage })));
const PrivacyPage = lazy(() => import('./pages/Public').then((module) => ({ default: module.PrivacyPage })));
const TermsPage = lazy(() => import('./pages/Public').then((module) => ({ default: module.TermsPage })));
const NotFoundPage = lazy(() => import('./pages/Public').then((module) => ({ default: module.NotFoundPage })));
const OverviewPage = lazy(() => import('./pages/Overview'));
const MonitoringPage = lazy(() => import('./pages/Monitoring'));
const AssetsPage = lazy(() => import('./pages/Assets'));
const IncidentsPage = lazy(() => import('./pages/Incidents').then((module) => ({ default: module.IncidentsPage })));
const IncidentDetailPage = lazy(() => import('./pages/Incidents').then((module) => ({ default: module.IncidentDetailPage })));
const InvestigationsPage = lazy(() => import('./pages/Investigations').then((module) => ({ default: module.InvestigationsPage })));
const InvestigationDetailPage = lazy(() => import('./pages/Investigations').then((module) => ({ default: module.InvestigationDetailPage })));
const IntelPage = lazy(() => import('./pages/Intel'));
const DetectionsPage = lazy(() => import('./pages/Detections'));
const PhishingPage = lazy(() => import('./pages/Phishing'));
const VulnerabilitiesPage = lazy(() => import('./pages/Vulnerabilities'));
const NetworkPage = lazy(() => import('./pages/Network'));
const ForensicsPage = lazy(() => import('./pages/Forensics'));
const AutomationPage = lazy(() => import('./pages/Automation'));
const ReportsPage = lazy(() => import('./pages/Reports'));
const SimulationsPage = lazy(() => import('./pages/Simulations'));
const SimulationDetailPage = lazy(() => import('./pages/SimulationDetail'));
const SettingsPage = lazy(() => import('./pages/Settings'));
const DemoDataPage = lazy(() => import('./pages/DemoData'));
const PeoplePage = lazy(() => import('./pages/People'));
const WebsitesPage = lazy(() => import('./pages/Websites'));
const WebsiteNewPage = lazy(() => import('./pages/WebsiteNew'));
const WebsiteDetailPage = lazy(() => import('./pages/WebsiteDetail'));

function ScrollToTop() {
  const { pathname } = useLocation();
  useEffect(() => { window.scrollTo({ top: 0, behavior: 'instant' as ScrollBehavior }); }, [pathname]);
  return null;
}

function RouteFallback() {
  return (
    <div style={{ minHeight: '40vh', display: 'grid', placeItems: 'center' }}>
      <span className="muted small">Loading view…</span>
    </div>
  );
}

export default function App() {
  const toasts = useToasts();
  return (
    <ToastContext.Provider value={{ push: toasts.push }}>
      <AppErrorBoundary>
        <BrowserRouter>
          <ThemeModeProvider>
            <AstryxProviders>
            <ScrollToTop />
            <AuthProvider>
              <Suspense fallback={<RouteFallback />}>
                <Routes>
                  <Route path="/" element={<LandingPage />} />
                  <Route path="/login" element={<LoginPage />} />
                  <Route path="/signup" element={<SignupPage />} />
                  <Route path="/privacy" element={<PrivacyPage />} />
                  <Route path="/terms" element={<TermsPage />} />
                  <Route path="/app" element={<Navigate to="/overview" replace />} />

                  <Route element={<RequireAuth><AppShellLayout /></RequireAuth>}>
                    <Route path="/overview" element={<OverviewPage />} />
                    <Route path="/monitoring" element={<MonitoringPage />} />
                    <Route path="/assets" element={<AssetsPage />} />
                    <Route path="/websites" element={<WebsitesPage />} />
                    <Route path="/websites/new" element={<WebsiteNewPage />} />
                    <Route path="/websites/:id" element={<WebsiteDetailPage />} />
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
                    <Route path="/demo-data" element={<DemoDataPage />} />
                  </Route>

                  <Route path="*" element={<NotFoundPage />} />
                </Routes>
              </Suspense>
            </AuthProvider>
            </AstryxProviders>
          </ThemeModeProvider>
        </BrowserRouter>
      </AppErrorBoundary>
      <ToastViewport toasts={toasts.toasts} onDismiss={toasts.dismiss} />
    </ToastContext.Provider>
  );
}
