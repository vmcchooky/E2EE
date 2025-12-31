import type { Conversation } from '@/types/chat'
import ChatCard from './ChatCard'
import { useAuthStore } from '@/stores/useAuthStore'
import { useChatStore } from '@/stores/useChatStore';
import { cn } from '@/lib/utils';
import UserAvatar from './UserAvatar';
import StatusBadge from './StatusBadge';
import UnReadCountBadge from './UnReadCountBadge';
import { useSocketStore } from '@/stores/useSocketStore';
import { useE2EEStore } from '@/stores/useE2EEStore';
import { useState, useEffect, useMemo, memo } from 'react';
import { Lock, AlertTriangle } from 'lucide-react';

const DirectMessageCard = memo(({ convo }: { convo: Conversation }) => {
  // All hooks must be called at the top level, before any conditional returns
  const { user } = useAuthStore();
  const { activeConversationId, setActiveConversation, messages, fetchMesssages, deleteConversation } = useChatStore();
  const { onlineUsers } = useSocketStore();
  const { isInitialized: e2eeInitialized, decryptMessage } = useE2EEStore();
  const [decryptedMessage, setDecryptedMessage] = useState<string | null>(null);
  const [isE2EE, setIsE2EE] = useState(false);
  const [decryptionFailed, setDecryptionFailed] = useState(false);

  // Memoize computed values to prevent unnecessary re-renders
  const otherUser = useMemo(() => {
    if (!user) return null;
    return convo.participants.find((participant) => participant._id !== user._id) || null;
  }, [convo.participants, user?._id]);

  const unreadCount = useMemo(() => {
    return user ? (convo.unreadCount[user._id] || 0) : 0;
  }, [convo.unreadCount, user?._id]);

  const lastMessageContent = useMemo(() => {
    return convo.lastMessage?.content ?? '';
  }, [convo.lastMessage?.content]);

  const senderId = useMemo(() => {
    return convo.lastMessage?.sender?._id;
  }, [convo.lastMessage?.sender?._id]);

  // Decrypt E2EE message if needed - MUST be called before any early returns
  useEffect(() => {
    // Only decrypt if we have all required data
    if (!user || !otherUser || !lastMessageContent || !e2eeInitialized) {
      setDecryptedMessage(null);
      setIsE2EE(false);
      setDecryptionFailed(false);
      return;
    }

    const isE2EEMessage = lastMessageContent.startsWith("E2EE:");
    setIsE2EE(isE2EEMessage);

    if (isE2EEMessage) {
      const ciphertext = lastMessageContent.substring(5);
      const isOwn = senderId ? String(senderId) === String(user._id) : false;

      // Determine which userId to use for decryption
      let decryptUserId: string;
      if (isOwn) {
        // My message: was encrypted with recipient's session key
        decryptUserId = String(otherUser._id);
      } else {
        // Other's message: decrypt with sender's session key
        decryptUserId = senderId ? String(senderId) : '';
      }

      if (!decryptUserId) {
        setDecryptedMessage("[Tin nhắn mã hóa]");
        setDecryptionFailed(true);
        return;
      }

      // Proper IDs for AAD matching
      const msgSenderId = String(senderId);
      const msgReceiverId = isOwn ? String(otherUser._id) : String(user._id);
      const counter = convo.lastMessage?.counter ?? undefined;

      decryptMessage(msgSenderId, msgReceiverId, ciphertext, counter).then((decrypted) => {
        if (decrypted) {
          setDecryptedMessage(decrypted);
          setDecryptionFailed(false);
        } else {
          setDecryptedMessage("[Tin nhắn mã hóa]");
          setDecryptionFailed(true);
        }
      }).catch((e) => {
        console.error("[DirectMessageCard] Decryption error:", e);
        setDecryptedMessage("[Tin nhắn mã hóa]");
        setDecryptionFailed(true);
      });
    } else {
      setDecryptedMessage(null);
      setDecryptionFailed(false);
    }
  }, [lastMessageContent, e2eeInitialized, senderId, user, otherUser, decryptMessage]);

  // Early returns after all hooks
  if (!user || !otherUser) { return null; }

  const displayMessage = decryptedMessage !== null ? decryptedMessage : lastMessageContent;


  const handleSelectConversation = async (id: string) => {
    setActiveConversation(convo._id);
    if (!messages[id]) {
      await fetchMesssages(id);
    }
  };

  const handleDelete = async (id: string) => {
    await deleteConversation(id);
  };


  return <ChatCard
    convoId={convo._id}
    name={otherUser.displayName ?? "Anonymous"}
    timestamp={convo.lastMessageAt ? new Date(convo.lastMessageAt) : undefined}
    isActive={activeConversationId === convo._id}
    onSelect={handleSelectConversation}
    onDelete={handleDelete}
    unreadCount={unreadCount}
    leftSection={
      <>
        <UserAvatar type="sidebar" name={otherUser.displayName ?? ""} avatarUrl={otherUser.avatarUrl} />
        <StatusBadge status={onlineUsers.includes(otherUser._id) ? "online" : "offline"}></StatusBadge>
        {unreadCount > 0 && <UnReadCountBadge unreadCount={unreadCount} />}
      </>
    }
    subtitle={
      <div className="flex items-center gap-1.5 flex-1 min-w-0">
        {isE2EE && (
          <div className="flex-shrink-0">
            {decryptionFailed ? (
              <AlertTriangle className="size-3 text-red-500" />
            ) : (
              <Lock className="size-3 text-green-500" />
            )}
          </div>
        )}
        <p className={
          cn("text-sm truncate flex-1 min-w-0",
            unreadCount > 0 ? "text-foreground font-medium" : "text-muted-foreground",
            decryptionFailed && "italic"
          )}>
          {displayMessage}
        </p>
      </div>
    }
  />
});

DirectMessageCard.displayName = 'DirectMessageCard';

export default DirectMessageCard