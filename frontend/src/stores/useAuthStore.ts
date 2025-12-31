import { create } from 'zustand';
import { toast } from 'sonner';
import { authService } from '@/services/authService';
import type { AuthState } from '@/types/store';
import { persist } from 'zustand/middleware';
import { useChatStore } from './useChatStore';
import { useE2EEStore } from './useE2EEStore';

// Flag
let isLoggingIn = false;

// Lock mechanism để tránh multiple refresh token calls cùng lúc
let refreshTokenPromise: Promise<string | null> | null = null;

export const useAuthStore = create<AuthState>()(
    persist(
        (set, get) => ({
            accessToken: null,
            user: null,
            loading: false,

            setAccessToken: (accessToken: string) => {
                set({ accessToken });
            },

            clearState: () => {
                set({ accessToken: null, user: null, loading: false })
                localStorage.removeItem('auth-storage');
                useChatStore.getState().reset();
            },

            signUp: async (username, password, email, firstname, lastname) => {
                try {
                    set({ loading: true });

                    await authService.signUp(username, password, email, firstname, lastname);

                    toast.success("Đăng ký thành công!", { duration: 3000 });
                } catch (error: any) {
                    const errorMessage =
                        error?.response?.data?.message ||
                        error?.response?.data?.detail ||
                        error?.message ||
                        "Đăng ký thất bại!";

                    toast.error(errorMessage, { duration: 3000 });
                    console.error(error);
                } finally {
                    set({ loading: false });
                }
            },

            login: async (username, password) => {
                try {
                    isLoggingIn = true;
                    set({ loading: true });

                    localStorage.removeItem('auth-storage');
                    useChatStore.getState().reset();

                    const response = await authService.login(username, password);

                    console.log('Login response:', response);

                    const accessToken = response?.data?.access_token || response?.access_token || response?.accessToken;
                    if (!accessToken) {
                        throw new Error("Không nhận được token từ server");
                    }

                    set({ accessToken });

                    try {
                        await get().fetchMe(true);
                        const user = get().user;

                        if (user?._id) {
                            const userId = String(user._id);
                            console.log(`[Auth] E2EE key will be initialized when user enters PIN for user ${userId}`);
                        }

                        useChatStore.getState().fetchConversations();

                        toast.success("Đăng nhập thành công!", { duration: 3000 });
                        isLoggingIn = false;
                    } catch (fetchError: any) {
                        set({ accessToken: null, user: null });
                        throw fetchError;
                    }
                } catch (error: any) {
                    const errorMessage =
                        error?.response?.data?.message ||
                        error?.response?.data?.detail ||
                        error?.message ||
                        "Đăng nhập thất bại!";

                    toast.error(errorMessage, { duration: 3000 });
                    console.error(error);
                } finally {
                    set({ loading: false });
                }
            },

            logout: async () => {
                try {
                    set({ loading: true });
                    await authService.logout();
                    set({ accessToken: null, user: null });

                    // Reset all stores to clear cached data
                    await useE2EEStore.getState().reset();
                    useChatStore.getState().reset();

                    toast.success("Đăng xuất thành công!", { duration: 3000 });
                } catch (error) {
                    set({ accessToken: null, user: null });
                    // Reset stores even on error
                    try {
                        await useE2EEStore.getState().reset();
                        useChatStore.getState().reset();
                    } catch (resetError) {
                        console.error("Failed to reset stores:", resetError);
                    }
                    toast.success("Đăng xuất thành công!", { duration: 3000 });
                    console.error(error);
                } finally {
                    set({ loading: false });
                }
            },

            fetchMe: async (silent: boolean = false) => {
                try {
                    set({ loading: true });
                    const user = await authService.fetchMe();
                    set({ user });
                } catch (error: any) {
                    console.error(error);
                    set({ accessToken: null, user: null });

                    // Only show toast if not silent (silent=true when called from login)
                    if (!silent) {
                        const errorMessage =
                            error?.response?.data?.message ||
                            error?.response?.data?.detail ||
                            "Phiên đã hết hạn, vui lòng đăng nhập lại!";
                        toast.error(errorMessage, { duration: 4000 });
                    }
                    throw error; // Re-throw so login() can handle it
                } finally {
                    set({ loading: false });
                }
            },
            refreshToken: async (silent: boolean = false) => {
                // If there's already a refresh token call in progress, wait for it
                if (refreshTokenPromise) {
                    console.log("[Auth] Refresh token already in progress, waiting...");
                    try {
                        return await refreshTokenPromise;
                    } catch (error) {
                        // If the pending refresh fails, we can try again
                        refreshTokenPromise = null;
                        throw error; // Re-throw to let caller handle
                    }
                }

                // Don't refresh token if user is currently logging in
                if (isLoggingIn) {
                    throw new Error("Login in progress, skipping token refresh");
                }

                // Create new refresh promise
                refreshTokenPromise = (async () => {
                    try {
                        if (!get().loading) {
                            set({ loading: true });
                        }
                        const accessToken = await authService.refreshToken();

                        if (accessToken) {
                            const hadAccessTokenBefore = !!get().accessToken;
                            set({ accessToken });

                            if (!hadAccessTokenBefore) {
                                // This is auto-login (no accessToken before) - fetch user and conversations
                                await get().fetchMe();
                                useChatStore.getState().fetchConversations();
                            } else if (!get().user) {
                                // AccessToken was refreshed but user data is missing - fetch user only
                                await get().fetchMe();
                            }
                            return accessToken;
                        }

                        throw new Error("Không nhận được access token mới");
                    } catch (error: any) {
                        console.error("Refresh token failed:", error);

                        // Only show toast if not silent and not logging in
                        if (!silent && !isLoggingIn) {
                            const errorMessage =
                                error?.response?.data?.message ||
                                error?.response?.data?.detail ||
                                "Phiên đã hết hạn, vui lòng đăng nhập lại!";
                            toast.error(errorMessage, { duration: 4000 });
                        }
                        get().clearState();
                        throw error;
                    } finally {
                        set({ loading: false });
                        refreshTokenPromise = null; // Clear promise when done
                    }
                })();

                return await refreshTokenPromise;
            },
        }),
        {
            name: 'auth-storage',
            partialize: (state) => ({
                user: state.user
            }),
        }
    )
);