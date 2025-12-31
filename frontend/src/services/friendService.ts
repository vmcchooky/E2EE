import api from "@/lib/axios";

export const friendService = {
  async searchByUsername(username: string) {
    const res = await api.get(`/users/search?username=${username}`);
    return res.data.user;
  },

  async sendFriendRequest(to: string, message?: string) {
    const res = await api.post("/friends/requests", { to_user: to, message });
    return res.data.message;
  },

  async getAllFriendRequest() {
    try {
      const res = await api.get("/friends/requests");
      console.log("API Response:", res.data);
      const { sent, received } = res.data.data;
      console.log("Sent requests:", sent);
      console.log("Received requests:", received);
      return { sent, received };
    } catch (error) {
      console.error("Lỗi khi gửi getAllFriendRequest", error);
      throw error;
    }
  },

  async acceptRequest(requestId: string) {
    try {
      console.log("Accepting request with ID:", requestId); // Debug log
      const res = await api.post(`/friends/requests/${requestId}/accept`);
      console.log("Accept response:", res.data); // Debug log
      return res.data;
    } catch (error: any) {
      console.error("Lỗi khi accept request:", error.response?.data || error);
      throw error;
    }
  },

  async declineRequest(requestId: string) {
    try {
      console.log("Declining request with ID:", requestId); // Debug log
      const res = await api.post(`/friends/requests/${requestId}/decline`);
      console.log("Decline response:", res.data); // Debug log
      return res.data;
    } catch (error: any) {
      console.error("Lỗi khi decline request:", error.response?.data || error);
      throw error;
    }
  },

  async getFriendList() {
    try {
      const res = await api.get("/friends");
      return res.data.data;
    } catch (error) {
      console.error("Lỗi khi gửi getFriendList", error);
      throw error;
    }
  },
};
