import { cn, formatMessageTime } from "@/lib/utils";
import type { Conversation, Message, Participant } from "@/types/chat"
import UserAvatar from "./UserAvatar";
import { Card } from "../ui/card";
import { Badge } from "../ui/badge";
import { Lock, AlertTriangle } from "lucide-react";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "../ui/tooltip";

interface MessageItemProps {
  message: Message;
  index: number;
  messages: Message[];
  selectedConvo: Conversation;
  lastMessageStatus: "delivered" | "seen";
}

const MessageItem = (
  { message, index, messages, selectedConvo, lastMessageStatus }: MessageItemProps
) => {
  const prev = messages[index - 1];

  // Safely calculate time difference (handle invalid dates)
  const currentTime = message.createdAt ? new Date(message.createdAt).getTime() : 0;
  const prevTime = prev?.createdAt ? new Date(prev.createdAt).getTime() : 0;
  const timeDiff = (currentTime && prevTime && !isNaN(currentTime) && !isNaN(prevTime))
    ? currentTime - prevTime
    : 0;

  const isGroupBreak =
    index === 0 ||
    message.senderId !== prev?.senderId ||
    timeDiff > 300000;

  const participant = selectedConvo.participants?.find(
    (p: Participant) => p._id?.toString() === message.senderId?.toString()
  );

  // Find latest own message in the current list (robust even if conversation.lastMessage lags)
  const lastOwnMessageId = (() => {
    for (let i = messages.length - 1; i >= 0; i--) {
      if (messages[i].isOwn) return messages[i]._id;
    }
    return undefined;
  })();

  // Check if this is a system message
  const isSystemMessage = message.isSystem || (message.content?.startsWith("SYSTEM:") ?? false);

  // Parse system message content
  let systemMessageText = "";
  if (isSystemMessage && message.content) {
    const parts = message.content.split(":");
    if (parts[1] === "user_left" && parts[3]) {
      systemMessageText = `${parts[3]} đã rời nhóm`;
    } else {
      systemMessageText = message.content.replace("SYSTEM:", "");
    }
  }

  // Render system message differently
  if (isSystemMessage) {
    return (
      <div className="flex justify-center my-2">
        <div className="px-3 py-1.5 bg-muted/50 rounded-full">
          <p className="text-xs text-muted-foreground text-center">
            {systemMessageText || message.content}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div
      className={cn(
        "flex gap-2 message-bounce mt-1",
        message.isOwn ? "justify-end" : "justify-start",
      )}
    >
      {/* avatar */}
      {!message.isOwn && (
        <div className="w-8">
          {isGroupBreak && (
            <UserAvatar
              type="chat"
              name={participant?.displayName ?? "Unknown"}
              avatarUrl={participant?.avatarUrl ?? undefined}
            />
          )}
        </div>
      )}

      {/* message */}
      <div
        className={cn(
          "max-w-xs lg:max-w-md space-y-1 flex flex-col",
          message.isOwn ? "items-end" : "items-start",
        )}
      >
        <Card
          className={cn(
            "p-3 relative",
            message.isOwn
              ? "bg-chat-bubble-sent text-chat-bubble-sent-fg border-0"
              : "bg-chat-bubble-received text-chat-bubble-received-fg",
            // E2EE styling
            message.isE2EE && !message.decryptionFailed && "ring-1 ring-green-500/30",
            message.decryptionFailed && "ring-1 ring-red-500/30 bg-red-50 dark:bg-red-950/20"
          )}
        >
          {/* E2EE indicator */}
          {message.isE2EE && (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <div className={cn(
                    "absolute -top-1 -right-1 rounded-full p-0.5",
                    message.decryptionFailed
                      ? "bg-red-500"
                      : "bg-green-500"
                  )}>
                    {message.decryptionFailed ? (
                      <AlertTriangle className="size-2.5 text-white" />
                    ) : (
                      <Lock className="size-2.5 text-white" />
                    )}
                  </div>
                </TooltipTrigger>
                <TooltipContent>
                  {message.decryptionFailed
                    ? "Không thể giải mã tin nhắn"
                    : "Tin nhắn được mã hóa E2EE"
                  }
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}

          <p className={cn(
            "text-sm leading-relaxed break-words",
            message.decryptionFailed && "italic text-muted-foreground"
          )}>
            {message.content}
          </p>
        </Card>

        <div
          className={cn(
            "flex flex-row items-center gap-2 px-1",
            message.isOwn ? "justify-end" : "justify-start",
          )}
        >
          {isGroupBreak && (
            <span className="text-xs text-muted-foreground">
              {formatMessageTime(new Date(message.createdAt))}
            </span>
          )}

          {/* E2EE badge */}
          {message.isE2EE && !message.decryptionFailed && (
            <Badge
              variant="outline"
              className="text-[10px] px-1.5 py-0.5 h-4 border-0 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400"
            >
              <Lock className="size-2 mr-0.5" />
              E2EE
            </Badge>
          )}

          {message.isOwn && message._id === lastOwnMessageId && (
            <Badge
              variant="outline"
              className={cn(
                "text-[10px] px-1.5 py-0.5 h-4 border-0",
                lastMessageStatus === "seen"
                  ? "bg-primary/20 text-primary"
                  : "bg-muted text-muted-foreground"
              )}
            >
              {lastMessageStatus}
            </Badge>
          )}
        </div>
      </div>
    </div>
  );
};

export default MessageItem;