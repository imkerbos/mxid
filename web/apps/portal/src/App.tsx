import { useEffect } from 'react'
import { Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom'
import {
  authApi,
  useAuthStore,
  useBootstrap,
  useTheme,
  currentReturnPath,
  safeReturnPath,
  ForcePasswordChange,
  portalApi,
} from '@mxid/shared'
import { Toaster } from '@mxid/shared/ui/toast'
import { resumeSSOIfAny } from './lib/sso'
import MainLayout from './components/layout/MainLayout'
import LoginPage from './pages/login'
import MagicLinkLoginPage from './pages/login/magic-link'
import SMSLoginPage from './pages/login/sms'
import AppsPage from './pages/apps'
import ConsentPage from './pages/consent'
import ProfilePage from './pages/profile'
import SecurityPage from './pages/security'
import AccessRequestsPage from './pages/access-requests'
import NoAccessPage from './pages/no-access'
import ForgotPasswordPage from './pages/password/forgot'
import ResetPasswordPage from './pages/password/reset'
import ForceMfaEnroll from './components/ForceMfaEnroll'
import StepUpModal from './components/StepUpModal'
import StepUpPage from './pages/step-up'

function AuthGuard({ children }: { children: React.ReactNode }) {
  const {
    user,
    loading,
    setUser,
    clear,
    mfaEnrollRequired,
    setMfaEnrollRequired,
    passwordChangeRequired,
    setPasswordChangeRequired,
  } = useAuthStore()
  const navigate = useNavigate()

  useEffect(() => {
    // Bootstrap: try the silent SSO bridge once (derive a portal session from
    // an existing SSO session, e.g. after switching back from console) before
    // falling back to the login form. skipAuthEvent keeps the probe's 401 from
    // racing the global mxid:unauthorized redirect.
    authApi.portalMe({ skipAuthEvent: true })
      .then(setUser)
      .catch(() =>
        authApi.portalSso()
          .then(() => authApi.portalMe({ skipAuthEvent: true }))
          .then(setUser)
          .catch(() => {
            clear()
            // Stash where they were so login can bounce them back (see
            // RedirectIfAuth / the login page's post-auth navigate).
            navigate('/login', { replace: true, state: { from: currentReturnPath() } })
          }),
      )
  }, [setUser, clear, navigate])

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
  }, [clear, navigate])

  // Mandatory MFA enrollment: when the backend gate reports the user must bind
  // a factor (403 / code 40331), flip a global flag so the whole portal is
  // replaced by the blocking enrollment screen — every other route/API would
  // 403 until a factor is bound, so we must not render partial pages.
  useEffect(() => {
    const onEnroll = () => setMfaEnrollRequired(true)
    window.addEventListener('mxid:mfa-enroll-required', onEnroll)
    return () => window.removeEventListener('mxid:mfa-enroll-required', onEnroll)
  }, [setMfaEnrollRequired])

  useEffect(() => {
    const onPwd = () => setPasswordChangeRequired(true)
    window.addEventListener('mxid:password-change-required', onPwd)
    return () => window.removeEventListener('mxid:password-change-required', onPwd)
  }, [setPasswordChangeRequired])

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
      </div>
    )
  }

  if (!user) return null

  // Block everything behind mandatory MFA enrollment until a factor is bound.
  if (mfaEnrollRequired) return <ForceMfaEnroll />

  // An administrator reset this account's password; every other portal call
  // 403s until a new one is chosen.
  if (passwordChangeRequired) {
    return (
      <ForcePasswordChange
        changePassword={(oldPwd, newPwd, totp) => portalApi.changePassword(oldPwd, newPwd, totp)}
        logout={() => authApi.portalLogout()}
        toLogin={() => navigate('/login', { replace: true })}
      />
    )
  }

  return <>{children}</>
}

function RedirectIfAuth({ children }: { children: React.ReactNode }) {
  const { user, loading, setUser, clear } = useAuthStore()
  const location = useLocation()

  useEffect(() => {
    authApi.portalMe().then(setUser).catch(() => clear())
  }, [setUser, clear])

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
      </div>
    )
  }

  if (user) {
    // SSO bounce: when the user lands on /login while already signed in and the
    // URL carries an in-flight protocol handshake (CAS / SAML / OIDC), resume
    // it instead of dropping them on /apps — the backend protocol handler
    // issues the ticket / code and 302s back to the original service. The
    // helper carries a loop tripwire: if the handshake never completes (e.g. a
    // half-cleared session bouncing us back to /login), it stops redirecting so
    // we fall through to /apps rather than hang.
    const sp = new URLSearchParams(location.search)
    if (resumeSSOIfAny(sp)) return null
    const from = safeReturnPath((location.state as { from?: string })?.from, '/apps')
    return <Navigate to={from} replace />
  }

  return <>{children}</>
}

export default function App() {
  // Pull bootstrap (branding + login methods + i18n) on first render so
  // document.title / primary color / favicon reflect admin settings
  // before the login page paints.
  useBootstrap()
  // Sync the theme store to the class the FOUC script already applied.
  const initTheme = useTheme((s) => s.init)
  useEffect(() => {
    initTheme()
  }, [initTheme])
  return (
    <>
      {/* Toaster lives at the app root, not inside MainLayout. Several screens
          render OUTSIDE that layout — /step-up, the forced MFA-enrollment and
          password-change gates — and every toast they raised was published to a
          host that was not mounted, so their errors were silently swallowed: a
          failed step-up looked like a dead button. Exactly one instance — two
          Toasters subscribe to the same queue and would double every toast. */}
      <Toaster />
      {/* Global step-up prompt: registers the handler the API client invokes
          when a request comes back step_up_required, then replays it. Mounted
          outside <Routes> so it survives navigation between pages. */}
      <StepUpModal />
      <Routes>
        <Route
          path="/login"
          element={
            <RedirectIfAuth>
              <LoginPage />
            </RedirectIfAuth>
          }
        />
        <Route
          path="/"
          element={
            <AuthGuard>
              <MainLayout />
            </AuthGuard>
          }
        >
          <Route index element={<Navigate to="/apps" replace />} />
          <Route path="apps" element={<AppsPage />} />
          <Route path="consent" element={<ConsentPage />} />
          <Route path="profile" element={<ProfilePage />} />
          <Route path="security" element={<SecurityPage />} />
          <Route path="access-requests" element={<AccessRequestsPage />} />
        </Route>
        <Route
          path="/login/magic-link"
          element={
            <RedirectIfAuth>
              <MagicLinkLoginPage />
            </RedirectIfAuth>
          }
        />
        <Route
          path="/login/sms"
          element={
            <RedirectIfAuth>
              <SMSLoginPage />
            </RedirectIfAuth>
          }
        />
        <Route path="/password/forgot" element={<ForgotPasswordPage />} />
        <Route path="/password/reset" element={<ResetPasswordPage />} />
        <Route path="/no-access" element={<NoAccessPage />} />
        {/* Standalone: the form-fill extension deep-links here to reopen the
            sudo window. Outside MainLayout — a single-purpose landing page,
            not a portal section. */}
        <Route
          path="/step-up"
          element={
            <AuthGuard>
              <StepUpPage />
            </AuthGuard>
          }
        />
        <Route path="*" element={<Navigate to="/apps" replace />} />
      </Routes>
    </>
  )
}
