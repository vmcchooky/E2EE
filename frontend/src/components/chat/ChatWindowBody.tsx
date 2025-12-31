import { useChatStore } from "@/stores/useChatStore";
import ChatWelcomeScreen from "./ChatWelcomeScreen";
import MessageItem from "./MessageItem";
import { useEffect, useRef } from "react";

const ChatWindowBody = () => {
  const {
    activeConversationId,
    conversations,
    messages: allMessages
  } = useChatStore();

  const messages = allMessages[activeConversationId!]?.items || [];
  const selectedConvo = conversations.find((c) => c._id === activeConversationId);

  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [activeConversationId, messages.length]);

  if (!selectedConvo) {
    return <ChatWelcomeScreen />;
  }

  if (!messages?.length) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        Không có tin nhắn nào trong cuộc trò chuyện này. Hãy bắt đầu cuộc trò chuyện!
      </div>
    );
  }

  return (
    <div className="p-4 bg-primary-foreground h-full flex flex-col overflow-hidden">
      <div
        ref={scrollRef}
        className="flex flex-col overflow-y-auto overflow-x-hidden beautiful-scrollbar"
      >
        {messages.map((message, index) => {
          const uniqueKey = message._id
            ? `msg-${message._id}`
            : `msg-${index}-${message.createdAt}-${message.senderId}`;

          return (
            <MessageItem
              key={uniqueKey}
              message={message}
              index={index}
              messages={messages}
              selectedConvo={selectedConvo}
              lastMessageStatus={"delivered"}
            />
          );
        })}
      </div>
    </div>
  );
};

export default ChatWindowBody;