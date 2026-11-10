import { BrowserRouter, Route, Routes } from "react-router-dom";
import { LoginPage } from "@/pages/LoginPage";
import { OnboardTenantPage } from "@/pages/OnboardTenantPage";
import { DashboardPage } from "@/pages/DashboardPage";
import { ClientsPage } from "@/pages/ClientsPage";
import { AppSetupPage } from "@/pages/AppSetupPage";
import { PolicyPage } from "@/pages/PolicyPage";
import { UsersPage } from "@/pages/UsersPage";
import { MySecurityPage } from "@/pages/MySecurityPage";
import { LaunchpadPage } from "@/pages/LaunchpadPage";
import { SwitchUserPage } from "@/pages/SwitchUserPage";
import { GroupsPage } from "@/pages/GroupsPage";
import { GoogleWorkspaceSettingsPage } from "@/pages/GoogleWorkspaceSettingsPage";
import { OrganizationalUnitsPage } from "@/pages/OrganizationalUnitsPage";
import { BrandingPage } from "@/pages/BrandingPage";
import { EndpointDevicesPage } from "@/pages/EndpointDevicesPage";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import { SessionRoute } from "@/components/SessionRoute";
import { ImpersonationBanner } from "@/components/ImpersonationBanner";
import { FeedbackProvider } from "@/components/feedback";

export function App() {
  return (
    <FeedbackProvider>
    <BrowserRouter>
      <ImpersonationBanner />
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/onboard" element={<OnboardTenantPage />} />
        <Route
          path="/"
          element={
            <SessionRoute>
              <DashboardPage />
            </SessionRoute>
          }
        />
        <Route
          path="/my-security"
          element={
            <SessionRoute>
              <MySecurityPage />
            </SessionRoute>
          }
        />
        <Route
          path="/apps"
          element={
            <SessionRoute>
              <LaunchpadPage />
            </SessionRoute>
          }
        />
        <Route
          path="/users"
          element={
            <ProtectedRoute>
              <UsersPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/switch-user"
          element={
            <ProtectedRoute>
              <SwitchUserPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/clients"
          element={
            <ProtectedRoute>
              <ClientsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/clients/setup"
          element={
            <ProtectedRoute>
              <AppSetupPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/policy"
          element={
            <ProtectedRoute>
              <PolicyPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/groups"
          element={
            <ProtectedRoute>
              <GroupsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/google-workspace"
          element={
            <ProtectedRoute>
              <GoogleWorkspaceSettingsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/google-workspace/organizational-units"
          element={
            <ProtectedRoute>
              <OrganizationalUnitsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/branding"
          element={
            <ProtectedRoute>
              <BrandingPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/endpoint-security"
          element={
            <ProtectedRoute>
              <EndpointDevicesPage />
            </ProtectedRoute>
          }
        />
      </Routes>
    </BrowserRouter>
    </FeedbackProvider>
  );
}
