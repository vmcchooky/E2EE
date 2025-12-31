import { useAuthStore } from '@/stores/useAuthStore';
import { useEffect, useRef, useState } from 'react';
import { Navigate, Outlet } from 'react-router';
import { SpinnerCustom } from '../ui/spinner';

const ProtectedRoute = () => {
    const { accessToken, user, loading, refreshToken, fetchMe, clearState } = useAuthStore();
    const [starting, setStarting] = useState(true);
    const [minLoading, setMinLoading] = useState(true);

    const hasInitialized = useRef(false);

    useEffect(() => {
        const timer = setTimeout(() => setMinLoading(false), 1000);


        if (hasInitialized.current) return;
        hasInitialized.current = true;
        const init = async () => {
            try {
                let token = accessToken;
                if (!token) {
                    const refreshed = await refreshToken();
                    token = typeof refreshed === 'string' ? refreshed : null;
                } else if (!user) {
                    await fetchMe();
                }
            } catch (error) {
                console.error('Init session failed:', error);
                clearState();
            } finally {
                setStarting(false);
            }
        };
        init();
        return () => clearTimeout(timer);
    }, []);

    if (loading || starting || minLoading) {
        return (
            <div className='flex h-screen items-center justify-center'>
                <SpinnerCustom />
            </div>
        )
    }

    if (!accessToken) {
        return <Navigate to="/login" replace />
    }

    return (
        <Outlet />
    )
}


export default ProtectedRoute