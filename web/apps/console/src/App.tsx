import { useEffect } from 'react'
import QRCode from 'qrcode'
import { Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import {
  useAuthStore,
  authApi,
  useBootstrap,
  useTheme,
  currentReturnPath,
  ForcePasswordChange,
  ForceMfaEnroll,
  consoleSecurityApi,
} from '@mxid/shared'
import MainLayout from './components/layout/MainLayout'
import StepUpModal from './components/StepUpModal'
import { Toaster } from './components/ui/toast'
import LoginPage from './pages/login'
import DashboardPage from './pages/dashboard'
import UsersPage from './pages/users'
import UserDetailPage from './pages/users/detail'
import OrgsPage from './pages/orgs'
import GroupsPage from './pages/groups'
import AppsPage from './pages/apps'
import IDPsPage from './pages/idps'
import TenantsPage from './pages/tenants'
import PermissionsPage from './pages/permissions'
import AccessApprovalsPage from './pages/access-approvals'
import AuditPage from './pages/audit'
import OffboardingPage from './pages/offboarding'
import DocsPage from './pages/docs'
import BrowserExtensionPage from './pages/browser-extension'
import AccountPage from './pages/account'
import SettingsLayout from './pages/settings/SettingsLayout'
import MailSMTPPage from './pages/settings/MailSMTP'
import SecurityPage from './pages/settings/Security'
import SystemVersionPage from './pages/settings/SystemVersion'
import AccessEligibilityPage from './pages/settings/AccessEligibility'
import {
  BrandingPage,
  LoginMethodsPage,
  ProtocolDefaultsPage,
  SMSPage,
  AuditPolicyPage,
  OffboardingWebhookPage,
  MFAPolicyPage,
  ConditionalAccessPage,
  LocalizationPage,
  LicensePage,
  MailTemplatesPage,
  ExternalURLsPage,
} from './pages/settings/SimplePages'
import { Navigate as RRNavigate } from 'react-router-dom'

function AuthGuard({ children }: { children: React.ReactNode }) {
  const {
    user,
    loading,
    setUser,
    clear,
    passwordChangeRequired,
    setPasswordChangeRequired,
    mfaEnrollRequired,
    setMfaEnrollRequired,
  } = useAuthStore()
  const navigate = useNavigate()

  useEffect(() => {
    // Bootstrap: if there's no console session yet, try the silent SSO bridge
    // once (derives a console session from an existing portal/SSO session)
    // before falling back to the login form. skipAuthEvent keeps the probe's
    // 401 from racing the global mxid:unauthorized redirect.
    authApi.me({ skipAuthEvent: true })
      .then(setUser)
      .catch(() =>
        authApi.sso()
          .then(() => authApi.me({ skipAuthEvent: true }))
          .then(setUser)
          .catch(() => {
            clear()
            // Stash where they were so the login page can bounce them back.
            navigate('/login', { replace: true, state: { from: currentReturnPath() } })
          }),
      )
  }, [])

  // The session died mid-session. Carry a reason to the login screen: without
  // it, submitting a filled-in form threw the user back to sign-in with the
  // typed content gone and no word about why — indistinguishable, from where
  // they sit, from the product crashing.
  useEffect(() => {
    const handler = () => {
      clear()
      navigate('/login', {
        replace: true,
        state: { from: currentReturnPath(), reason: 'session-expired' },
      })
    }
    window.addEventListener('mxid:unauthorized', handler)
    return () => window.removeEventListener('mxid:unauthorized', handler)
  }, [])

  // The account owes a password change: an admin reset it, or it is the seeded
  // administrator, whose password is published in a public repository. Every
  // other console call 403s until it is done.
  useEffect(() => {
    const onPwd = () => setPasswordChangeRequired(true)
    window.addEventListener('mxid:password-change-required', onPwd)
    return () => window.removeEventListener('mxid:password-change-required', onPwd)
  }, [setPasswordChangeRequired])

  // Policy requires MFA and this account has no factor. Every other console
  // call 403s until one is bound — including the password change above, which
  // is itself a high-risk operation requiring MFA. Without this screen the
  // seeded administrator was shown a password form that answered every
  // submission with "mfa enrollment required" and offered no way to enrol.
  useEffect(() => {
    const onEnroll = () => setMfaEnrollRequired(true)
    window.addEventListener('mxid:mfa-enroll-required', onEnroll)
    return () => window.removeEventListener('mxid:mfa-enroll-required', onEnroll)
  }, [setMfaEnrollRequired])

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
      </div>
    )
  }

  if (!user) return null

  // MFA first: on the console a password change requires a factor, so the
  // other order is a dead end.
  if (mfaEnrollRequired) {
    return (
      <ForceMfaEnroll
        setupTOTP={() => consoleSecurityApi.setupTOTP()}
        verifyTOTP={(code) => consoleSecurityApi.verifyTOTP(code)}
        logout={() => authApi.logout()}
        toQRDataURL={(url) => QRCode.toDataURL(url, { width: 220, margin: 1 })}
        onEnrolled={() => navigate('/dashboard', { replace: true })}
        toLogin={() => navigate('/login', { replace: true })}
      />
    )
  }

  if (passwordChangeRequired) {
    return (
      <ForcePasswordChange
        changePassword={(oldPwd, newPwd, totp) => consoleSecurityApi.changePassword(oldPwd, newPwd, totp)}
        logout={() => authApi.logout()}
        toLogin={() => navigate('/login', { replace: true })}
      />
    )
  }

  return <>{children}</>
}

export default function App() {
  // Apply branding (title, primary color, custom CSS) before anything paints.
  useBootstrap()
  // Sync the theme store to the class the FOUC script already applied.
  const initTheme = useTheme((s) => s.init)
  useEffect(() => {
    initTheme()
  }, [initTheme])

  // <Routes> deliberately carries no key. Keying it by pathname is the
  // framer-motion page-transition recipe, but that recipe needs an
  // <AnimatePresence> to mean anything and there is none here — so the key
  // bought no animation and instead unmounted AuthGuard, MainLayout and the
  // page on every navigation, refetching the entire shell each time.
  return (
    <>
      {/* Toaster at the app root, not inside MainLayout: the login screen and
          the forced password-change gate render outside that layout, so every
          toast they raised went to a host that was not mounted and vanished.
          Exactly one instance — two Toasters share the queue and double
          every toast. */}
      <Toaster />
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/*"
          element={
            <AuthGuard>
              <MainLayout>
                <StepUpModal />
                <Routes>
                  <Route path="/" element={<Navigate to="/dashboard" replace />} />
                  <Route path="/dashboard" element={<DashboardPage />} />
                  <Route path="/users" element={<UsersPage />} />
                  <Route path="/users/:id" element={<UserDetailPage />} />
                  <Route path="/orgs" element={<OrgsPage />} />
                  <Route path="/groups" element={<GroupsPage />} />
                  <Route path="/apps" element={<AppsPage />} />
                  <Route path="/idps" element={<IDPsPage />} />
                  <Route path="/tenants" element={<TenantsPage />} />
                  <Route path="/permissions" element={<PermissionsPage />} />
                  <Route path="/access-approvals" element={<AccessApprovalsPage />} />
                  <Route path="/audit" element={<AuditPage />} />
                  <Route path="/offboarding" element={<OffboardingPage />} />
                  <Route path="/docs" element={<DocsPage />} />
                  <Route path="/browser-extension" element={<BrowserExtensionPage />} />
                  <Route path="/account" element={<AccountPage />} />
                  <Route path="/settings" element={<SettingsLayout />}>
                    <Route index element={<RRNavigate to="/settings/mail/smtp" replace />} />
                    <Route path="mail/smtp" element={<MailSMTPPage />} />
                    <Route path="mail/templates" element={<MailTemplatesPage />} />
                    <Route path="sms" element={<SMSPage />} />
                    <Route path="security" element={<SecurityPage />} />
                    <Route path="mfa" element={<MFAPolicyPage />} />
                    <Route path="conditional-access" element={<ConditionalAccessPage />} />
                    <Route path="login-methods" element={<LoginMethodsPage />} />
                    <Route path="protocol-defaults" element={<ProtocolDefaultsPage />} />
                    <Route path="branding" element={<BrandingPage />} />
                    <Route path="localization" element={<LocalizationPage />} />
                    <Route path="audit-policy" element={<AuditPolicyPage />} />
                    <Route path="offboarding-webhook" element={<OffboardingWebhookPage />} />
                    <Route path="license" element={<LicensePage />} />
                    <Route path="external-urls" element={<ExternalURLsPage />} />
                    <Route path="system-version" element={<SystemVersionPage />} />
                    <Route path="access-eligibility" element={<AccessEligibilityPage />} />
                  </Route>
                  <Route path="*" element={<Navigate to="/dashboard" replace />} />
                </Routes>
              </MainLayout>
            </AuthGuard>
          }
        />
      </Routes>
    </>
  )
}

