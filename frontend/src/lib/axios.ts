import { useAuthStore } from '@/stores/useAuthStore';
import axios from 'axios';

const api = axios.create({
    baseURL: 'http://localhost:8000/api',
    withCredentials: true,
});

api.interceptors.request.use((config) => {
    const accessToken = useAuthStore.getState().accessToken;
    if (accessToken) {
        config.headers.Authorization = `Bearer ${accessToken}`;
    }
    return config;
});

api.interceptors.response.use(
    (response) => response,
    async (error) => {
        const originalRequest = error.config;

        if (originalRequest._retry || originalRequest.url.includes("/auth/signin") || originalRequest.url.includes("/auth/refresh-token")) {
            return Promise.reject(error);
        }

        if (error.response?.status === 401 || error.response?.status === 403) {
            // For 403, log for debugging
            if (error.response?.status === 403) {
                console.warn("[Axios] Received 403 Forbidden, attempting token refresh");
            }

            // Use the store's refreshToken which has built-in lock mechanism
            try {
                originalRequest._retry = true;
                const newToken = await useAuthStore.getState().refreshToken(true); // silent=true to avoid duplicate toasts
                if (newToken) {
                    originalRequest.headers.Authorization = `Bearer ${newToken}`;
                    return api(originalRequest);
                }
                useAuthStore.getState().clearState();
                return Promise.reject(error);
            } catch (refreshError) {
                useAuthStore.getState().clearState();
                return Promise.reject(error);
            }
        }

        return Promise.reject(error);
    }
);

export default api;