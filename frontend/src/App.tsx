import { BrowserRouter, Routes, Route, useLocation } from 'react-router'
import LoginPage from './pages/LoginPage'
import RegisterPage from './pages/RegisterPage'
import ChatAppPage from './pages/ChatAppPage'
import JoinGroupPage from './pages/JoinGroupPage'
import { Toaster } from 'sonner';
import ProtectedRoute from './components/auth/protected-route';
import { useThemeStore } from './stores/useThemeStore';
import { useEffect, useRef, useState } from 'react';
import { useAuthStore } from './stores/useAuthStore';
import { useSocketStore } from './stores/useSocketStore';
import { useE2EEStore } from './stores/useE2EEStore';
import { useChatStore } from './stores/useChatStore';
import { e2eeService } from './services/e2eeService';
import KeyChangeWarningDialog from './components/e2ee/KeyChangeWarningDialog';
import PINDialog from './components/e2ee/PINDialog';
import { getOrCreateDeviceId, getOrCreateDeviceName } from './lib/keyStore';

function AppContent() {
  const location = useLocation();
  const { isDark, setTheme } = useThemeStore();
  const { accessToken, user, refreshToken } = useAuthStore();
  const { connectSocket, disconnectSocket, resetReconnect } = useSocketStore();
  const { initialize: initializeE2EE, myPublicKeyBase64, myFingerprint, isInitialized: e2eeInitialized } = useE2EEStore();
  const publicKeyRegisteredRef = useRef(false);
  const [showPINDialog, setShowPINDialog] = useState(false);
  const [pinError, setPinError] = useState<string | undefined>();
  const pendingE2EEInitRef = useRef(false);
  const [failedPinAttempts, setFailedPinAttempts] = useState(0);
  const [nextAllowedPinTime, setNextAllowedPinTime] = useState<number | null>(null);
  const hasCheckedAuthRef = useRef(false);

  useEffect(() => {
    setTheme(isDark);
  }, [isDark]);

  // Check refreshToken in cookie and auto-login on app startup
  useEffect(() => {
    if (hasCheckedAuthRef.current) return;
    hasCheckedAuthRef.current = true;

    const checkAuth = async () => {
      // If already have accessToken and user, no need to check
      if (accessToken && user) {
        return;
      }

      // Try to refresh token from cookie (silent=true to avoid showing error toast)
      try {
        const newToken = await refreshToken(true);
        if (newToken) {
          console.log("[App] Auto-logged in from refresh token");
        }
      } catch (error) {
        // Refresh token failed or doesn't exist - user needs to login
        // Don't show error toast here (silent mode)
        console.log("[App] No valid refresh token, user needs to login");
      }
    };

    checkAuth();
  }, []); // Only run once on mount


  // WebSocket connection - only depends on auth state
  useEffect(() => {
    if (accessToken && user) {
      resetReconnect(); // Reset reconnect counter on login
      connectSocket();
    }
    return () => {
      disconnectSocket();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accessToken, user]);

  // Show PIN dialog for E2EE - separate effect
  // Don't show PIN dialog on join-group page (user might not be fully authenticated yet)
  useEffect(() => {
    const isJoinGroupPage = location.pathname.startsWith('/join-group');
    if (accessToken && user && !e2eeInitialized && !pendingE2EEInitRef.current && !isJoinGroupPage) {
      setShowPINDialog(true);
    } else if (isJoinGroupPage) {
      // Don't show PIN dialog on join-group page
      setShowPINDialog(false);
    }
  }, [accessToken, user, e2eeInitialized, location.pathname]);

  // Register public key with server after E2EE is initialized
  useEffect(() => {
    // Only register if all conditions are met AND accessToken is available AND not already registered
    if (e2eeInitialized && myPublicKeyBase64 && myFingerprint && user && accessToken && !publicKeyRegisteredRef.current) {
      publicKeyRegisteredRef.current = true; // Prevent multiple calls

      // Add a small delay to ensure token is ready
      const timeoutId = setTimeout(() => {
        const deviceId = getOrCreateDeviceId();
        const deviceName = getOrCreateDeviceName();

        e2eeService.registerPublicKey(myPublicKeyBase64, myFingerprint, deviceId, deviceName)
          .then(() => {
            console.log("[E2EE] Public key registered with server (device:", deviceName, ")");
          })
          .catch((err) => {
            // Reset flag on error so it can retry
            publicKeyRegisteredRef.current = false;

            // Only log if it's not a 403 (might be duplicate registration)
            if (err.response?.status !== 403) {
              console.error("[E2EE] Failed to register public key:", err);
            } else {
              console.warn("[E2EE] Public key registration returned 403 (might be duplicate or auth issue)");
            }
          });
      }, 500); // Small delay to ensure token is set

      return () => clearTimeout(timeoutId);
    }
  }, [e2eeInitialized, myPublicKeyBase64, myFingerprint, user, accessToken]);

  const handlePINConfirm = async (pin: string) => {
    setPinError(undefined);

    // Rate limiting: check if we're currently in a backoff window
    const now = Date.now();
    if (nextAllowedPinTime && now < nextAllowedPinTime) {
      const remainingMs = nextAllowedPinTime - now;
      const remainingSec = Math.ceil(remainingMs / 1000);
      setPinError(`Bạn đã nhập sai quá nhiều lần. Vui lòng thử lại sau ${remainingSec}s.`);
      return;
    }

    pendingE2EEInitRef.current = true;
    try {
      // PIN is used temporarily in memory only
      await initializeE2EE(pin);

      // Kiểm tra xem E2EE đã init thành công chưa
      const { isInitialized } = useE2EEStore.getState();
      if (!isInitialized) {
        // Xem như PIN sai hoặc không thể giải mã
        const newAttempts = failedPinAttempts + 1;
        setFailedPinAttempts(newAttempts);

        // Tăng delay theo số lần sai (ví dụ: 2s, 4s, 6s, ... tối đa 30s)
        const delayMs = Math.min(30000, newAttempts * 2000);
        setNextAllowedPinTime(Date.now() + delayMs);

        const delaySec = Math.ceil(delayMs / 1000);
        setPinError(`PIN không đúng hoặc không thể giải mã khóa riêng. Vui lòng thử lại sau ${delaySec}s.`);
        return;
      }

      // Nếu thành công: reset đếm và clear backoff
      setFailedPinAttempts(0);
      setNextAllowedPinTime(null);

      // Clear dialog
      setShowPINDialog(false);

      // After E2EE is initialized, re-decrypt messages for active conversation
      const chatStore = useChatStore.getState();
      const activeId = chatStore.activeConversationId;
      if (activeId) {
        chatStore.setActiveConversation(activeId);
      }
    } catch (error) {
      console.error("[E2EE] Failed to initialize with PIN:", error);
      setPinError("PIN không đúng hoặc không thể giải mã khóa riêng");
    } finally {
      pendingE2EEInitRef.current = false;
      // PIN variable is automatically garbage collected (not stored)
    }
  };

  const handlePINCancel = () => {
    setShowPINDialog(false);
    setPinError(undefined);
    // User cancelled - they can't use E2EE features
    console.warn("[E2EE] User cancelled PIN entry - E2EE features disabled");
  };

  return (
    <>
      <Toaster richColors duration={3000} />
      {/* E2EE Key Change Warning Dialog */}
      <KeyChangeWarningDialog />
      {/* PIN Dialog for E2EE initialization */}
      {accessToken && user && (
        <PINDialog
          open={showPINDialog && !e2eeInitialized && !pendingE2EEInitRef.current}
          onConfirm={handlePINConfirm}
          onCancel={handlePINCancel}
          error={pinError}
        />
      )}
      <Routes>
        {/* Public Routes */}

        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/join-group/:inviteCode" element={<JoinGroupPage />} />
        <Route path="/join-group" element={<JoinGroupPage />} />

        {/* Private Routes */}
        <Route element={<ProtectedRoute />}>
          <Route path="/" element={<ChatAppPage />} />
        </Route>

      </Routes>
    </>
  );
}

function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  );
}

export default App
