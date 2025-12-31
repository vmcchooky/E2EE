import { useEffect, useRef, useState } from "react";
import { useFriendStore } from "@/stores/useFriendStore";
import { DialogContent, DialogDescription, DialogHeader, DialogTitle } from "../ui/dialog";
import { MessageCircleMore, Users } from "lucide-react";
import { Card } from "../ui/card";
import UserAvatar from "../chat/UserAvatar";
import { useChatStore } from "@/stores/useChatStore";
import { useAuthStore } from "@/stores/useAuthStore";

const FriendListModal = () => {
  const friends = useFriendStore((state) => state.friends) || [];
  const getFriends = useFriendStore((state) => state.getFriends);
  const { conversations, createConversation, setActiveConversation, fetchMesssages } = useChatStore();
  const { user } = useAuthStore();
  const hasFetchedRef = useRef(false);
  const [isCreating, setIsCreating] = useState<string | null>(null); // Track which friend is being processed

  useEffect(() => {
    // Only fetch if friends list is empty and we haven't fetched yet
    if (friends.length === 0 && !hasFetchedRef.current) {
      hasFetchedRef.current = true;
      void getFriends();
    }
    // Reset flag when friends list becomes non-empty (e.g., after accepting a request)
    if (friends.length > 0) {
      hasFetchedRef.current = false;
    }
  }, [friends.length, getFriends]);

  const handleAddConversation = async (friendId: string) => {
    if (!friendId || isCreating === friendId) {
      // Prevent multiple clicks on the same friend
      return;
    }

    if (!user) {
      console.warn("User not found");
      return;
    }

    setIsCreating(friendId);

    try {
      // Check if conversation already exists with this friend
      const existingConversation = conversations.find((conv) => {
        if (conv.type !== "direct") return false;
        // Check if this friend is a participant
        return conv.participants.some((p) => String(p._id) === String(friendId));
      });

      if (existingConversation) {
        // Conversation already exists, just set it as active and fetch messages
        await setActiveConversation(existingConversation._id);
        await fetchMesssages(existingConversation._id);
      } else {
        // Create new conversation
        await createConversation("direct", "", [friendId]);
      }
    } catch (error) {
      console.error("Error handling conversation:", error);
    } finally {
      setIsCreating(null);
    }
  };

  return (
    <DialogContent className="glass max-w-md">
      <DialogHeader>
        <DialogTitle className="flex items-center gap-2 text-xl capitalize">
          <MessageCircleMore className="size-5" />
          bắt đầu hội thoại mới
        </DialogTitle>
        <DialogDescription>
          Chọn một người bạn để mở cuộc trò chuyện trực tiếp.
        </DialogDescription>
      </DialogHeader>

      {/* friends list */}
      <div className="space-y-4">
        <h1 className="text-sm font-semibold text-muted-foreground mb-3 uppercase tracking-wide">
          danh sách bạn bè
        </h1>

        <div className="space-y-2 max-h-60 overflow-y-auto">
          {friends.map((friend, idx) => {
            const isProcessing = isCreating === friend._id;
            return (
              <Card
                onClick={() => !isProcessing && handleAddConversation(friend._id)}
                key={friend._id ?? friend.username ?? idx}
                className={`p-3 transition-smooth hover:shadow-soft glass hover:bg-muted/30 group/friendCard ${isProcessing ? "opacity-50 cursor-not-allowed" : "cursor-pointer"
                  }`}
              >
                <div className="flex items-center gap-3">
                  {/* avatar */}
                  <div className="relative">
                    <UserAvatar
                      type="sidebar"
                      name={friend.displayName ?? "Người dùng"}
                      avatarUrl={friend.avatarUrl ?? undefined}
                    />
                  </div>

                  {/* info */}
                  <div className="flex-1 min-w-0 flex flex-col">
                    <h2 className="font-semibold text-sm truncate">
                      {friend.displayName}
                    </h2>
                    <span className="text-sm text-muted-foreground">
                      @{friend.username}
                    </span>
                  </div>
                </div>
              </Card>
            );
          })}

          {friends.length === 0 && (
            <div className="text-center py-8 text-muted-foreground">
              <Users className="size-12 mx-auto mb-3 opacity-50" />
              Chưa có bạn bè. Thêm bạn vô để tám!
            </div>
          )}
        </div>
      </div>
    </DialogContent>
  );
};

export default FriendListModal;
