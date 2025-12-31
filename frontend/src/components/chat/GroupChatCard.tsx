import { cn } from '@/lib/utils';
import { useAuthStore } from '@/stores/useAuthStore';
import { useChatStore } from '@/stores/useChatStore';
import type { Conversation } from '@/types/chat'
import ChatCard from './ChatCard';
import UnReadCountBadge from './UnReadCountBadge';
import GroupChatAvatar from './GroupChatAvatar';

const GroupChatCard = ({ convo }: { convo: Conversation }) => {
  const { user } = useAuthStore();
  const { activeConversationId, setActiveConversation, messages, fetchMesssages, deleteConversation } = useChatStore();

  if (!user) { return null; }

  const unreadCount = convo.unreadCount[user._id];
  const name = convo.group?.name ?? "";
  const handleSelectConversation = async (id: string) => {
    setActiveConversation(convo._id);
    if (!messages[id]) {
      await fetchMesssages(id);
    }
  };

  const handleDelete = async (id: string) => {
    await deleteConversation(id);
  };

  return (
    <ChatCard
      convoId={convo._id}
      name={name}
      timestamp={convo.lastMessage?.createdAt ? new Date(convo.lastMessage.createdAt) : undefined}
      isActive={activeConversationId === convo._id}
      onSelect={handleSelectConversation}
      onDelete={handleDelete}
      unreadCount={unreadCount}
      leftSection={<>
        {unreadCount > 0 && <UnReadCountBadge unreadCount={unreadCount} />}
        <GroupChatAvatar participants={convo.participants} type="chat" />
      </>}
      subtitle={
        <p className='text-sm truncare text-muted-foreground'>{convo.participants.length} thành viên</p>
      }
    />
  )
}

export default GroupChatCard