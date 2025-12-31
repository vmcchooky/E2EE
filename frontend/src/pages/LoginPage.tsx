import { LoginForm } from '@/components/auth/login-form'
import { useAuthStore } from '@/stores/useAuthStore'
import { Navigate, useLocation } from 'react-router'

const LoginPage = () => {
  const { accessToken } = useAuthStore();
  const location = useLocation();
  const returnTo = (location.state as any)?.returnTo || "/";

  // Redirect to returnTo (or home) if already logged in
  if (accessToken) {
    return <Navigate to={returnTo} replace />
  }

  return (
    <div className="bg-muted flex min-h-svh flex-col items-center justify-center p-6 md:p-10 absolute inset-0 z-0 bg-gradient-purple">
      <div className="w-full max-w-sm md:max-w-4xl">
        <LoginForm returnTo={returnTo} />
      </div>
    </div>
  )
}

export default LoginPage