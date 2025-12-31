import api from "@lib/axios"

export const authService = {
    signUp: async (username: string, password: string, email: string, firstname: string, lastname: string) => {
        const response = await api.post('/auth/signup', {
            username,
            password,
            email,
            firstname,
            lastname
        });
        return response.data;
    },

    login: async (username: string, password: string) => {
        const response = await api.post('/auth/signin', {
            username,
            password
        }, { withCredentials: true });
        return response.data;
    },
    logout: async () => {
        const response = await api.post('/auth/logout', {}, { withCredentials: true });
        return response.data;
    },
    fetchMe: async () => {
        const response = await api.get('/users/me', { withCredentials: true });
        // Backend trả về BaseResponse với data chứa user object
        return response.data?.data?.user || response.data?.user;
    },
    refreshToken: async () => {
        const response = await api.post('/auth/refresh-token', {}, { withCredentials: true });
        console.log('Refresh token response:', response);
        return response.data?.data?.access_token || response.data?.access_token;
    }
}