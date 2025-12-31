import { friendService } from "@/services/friendService";
import type { FriendState } from "@/types/store";
import { create } from "zustand";

// Flag to prevent duplicate requests
let isFetchingFriends = false;

export const useFriendStore = create<FriendState>((set, get) => ({
  friends: [],
  loading: false,
  receivedList: [],
  sentList: [],
  searchByUsername: async (username) => {
    try {
      set({ loading: true });

      const user = await friendService.searchByUsername(username);

      return user;
    } catch (error) {
      console.error("Lỗi xảy ra khi tìm user bằng username", error);
      return null;
    } finally {
      set({ loading: false });
    }
  },
  addFriend: async (to, message) => {
    try {
      set({ loading: true });
      const resultMessage = await friendService.sendFriendRequest(to, message);
      return resultMessage;
    } catch (error: any) {
      const errorMessage = error?.response?.data?.message || "Lỗi xảy ra khi gửi kết bạn. Hãy thử lại";
      return errorMessage;
    } finally {
      set({ loading: false });
    }
  },
  getAllFriendRequests: async () => {
    try {
      set({ loading: true });

      const result = await friendService.getAllFriendRequest();

      console.log("Result in store:", result);

      if (!result) {
        console.warn("No result returned from getAllFriendRequest");
        return;
      }

      const { received, sent } = result;

      console.log("Setting state - Received:", received, "Sent:", sent);

      set({ receivedList: received || [], sentList: sent || [] });
    } catch (error) {
      console.error("Lỗi xảy ra khi getAllFriendRequests", error);
      set({ receivedList: [], sentList: [] });
    } finally {
      set({ loading: false });
    }
  },
  acceptRequest: async (requestId) => {
    try {
      set({ loading: true });
      console.log("Store - Accepting request:", requestId);

      await friendService.acceptRequest(requestId);

      console.log("Store - Request accepted successfully, updating state");

      // Xóa request khỏi receivedList sau khi accept thành công
      set((state) => ({
        receivedList: state.receivedList.filter((r) => r._id !== requestId),
      }));

      // Refresh danh sách bạn bè
      await get().getFriends();

    } catch (error: any) {
      console.error("Lỗi xảy ra khi acceptRequest", error);
      throw error; // Throw error để component có thể catch
    } finally {
      set({ loading: false });
    }
  },
  declineRequest: async (requestId) => {
    try {
      set({ loading: true });
      console.log("Store - Declining request:", requestId);

      await friendService.declineRequest(requestId);

      console.log("Store - Request declined successfully, updating state");

      set((state) => ({
        receivedList: state.receivedList.filter((r) => r._id !== requestId),
      }));

    } catch (error: any) {
      console.error("Lỗi xảy ra khi declineRequest", error);
      throw error;
    } finally {
      set({ loading: false });
    }
  },
  getFriends: async () => {
    // Prevent duplicate requests
    if (isFetchingFriends) {
      console.log("[FriendStore] Already fetching friends, skipping duplicate request");
      return;
    }

    try {
      isFetchingFriends = true;
      set({ loading: true });
      const friends = await friendService.getFriendList();
      console.log("Loaded friends:", friends);
      set({ friends: friends || [] });
    } catch (error) {
      console.error("Lỗi xảy ra khi load friends", error);
      set({ friends: [] });
    } finally {
      isFetchingFriends = false;
      set({ loading: false });
    }
  },
}));
