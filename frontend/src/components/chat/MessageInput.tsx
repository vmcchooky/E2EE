import { useAuthStore } from "@/stores/useAuthStore"
import { useState, useEffect } from "react"
import { Button } from "../ui/button";
import { ImagePlus, Send, Lock, LockOpen, RefreshCw } from "lucide-react";
import { Input } from "../ui/input";
import EmojiPicker from "./EmojiPicker";
import type { Conversation } from "@/types/chat";
import { useChatStore } from "@/stores/useChatStore";
import { toast } from "sonner";
import { useE2EEStore } from "@/stores/useE2EEStore";
import { e2eeService } from "@/services/e2eeService";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "../ui/tooltip";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

const MessageInput = ({ selectedConvo }: { selectedConvo: Conversation }) => {
  const { user } = useAuthStore();
  const {
    sendDirectMessage,
    sendGroupMessage,
    activeConversationId,
    triggerRedecryption
  } = useChatStore();

  // Subscribe to E2EE store changes to re-decrypt messages when keys arrive
  useEffect(() => {
    const unsubscribe = useE2EEStore.subscribe(
      (state, prevState) => {
        if (!activeConversationId) return;

        const newKeys = state.groupSessionKeys?.[activeConversationId];
        const oldKeys = prevState?.groupSessionKeys?.[activeConversationId];

        // Shallow comparison is usually enough for reference changes
        if (newKeys !== oldKeys) {
          console.log(`[MessageInput] Keys updated for ${activeConversationId}, triggering re-decryption`);
          triggerRedecryption(activeConversationId);
        }
      }
    );
    return () => unsubscribe();
  }, [activeConversationId, triggerRedecryption]);

  const [value, setValue] = useState("");
  const [isEstablishingE2EE, setIsEstablishingE2EE] = useState(false);

  // E2EE Store
  const {
    hasSessionWith,
    hasGroupSession,
    // initiateKeyExchange removed
    // initiateKeyExchange removed
    initiateGroupKeyExchange,
    rekeyDirectChat,
    deleteSession,
    registerUserPublicKey,
    encryptMessage,
    encryptGroupMessage,
    isInitialized: e2eeInitialized
  } = useE2EEStore();

  if (!user) return null;

  // Get the other user in direct conversation
  const getOtherUser = () => {
    if (selectedConvo.type !== "direct") return null;
    return selectedConvo.participants.find((p) => p._id !== user._id);
  };

  const otherUser = getOtherUser();
  const isDirectE2EEEnabled = selectedConvo.type === "direct" && otherUser && hasSessionWith(otherUser._id);
  const isGroupE2EEEnabled = selectedConvo.type === "group" && hasGroupSession(selectedConvo._id);
  const isE2EEEnabled = isDirectE2EEEnabled || isGroupE2EEEnabled;

  // Check if user is group owner (only owner can re-key group)
  const isGroupOwner = selectedConvo.type === "group" && selectedConvo.group?.createdBy === user?._id;

  // Check if there are any options to show in the dropdown
  const hasDropdownOptions =
    (selectedConvo.type === "direct" && !!otherUser) ||
    (selectedConvo.type === "group" && isGroupOwner);

  // Initialize E2EE session for direct chats
  const initializeE2EESession = async () => {
    if (selectedConvo.type === "direct") {
      if (!otherUser || hasSessionWith(otherUser._id)) return;
    } else if (selectedConvo.type === "group") {
      if (hasGroupSession(selectedConvo._id)) return;
    } else {
      return;
    }

    setIsEstablishingE2EE(true);
    try {
      if (selectedConvo.type === "direct") {
        // Direct chat E2EE (existing logic)
        if (!otherUser) return;

        // 1. Get all other user's public keys from server (multi-device)
        const publicKeys = await e2eeService.getUserPublicKeys(otherUser._id);

        if (!publicKeys || publicKeys.length === 0) {
          toast.info("Người dùng này chưa hỗ trợ mã hóa E2EE");
          return;
        }

        // 2. Register their public keys (TOFU check) - use first key for TOFU
        const firstKey = publicKeys[0];
        const { status } = await registerUserPublicKey(
          otherUser._id,
          otherUser.displayName || otherUser._id,
          firstKey.public_key
        );

        if (status === "changed") {
          toast.warning("Khóa của người dùng đã thay đổi! Vui lòng xác minh.");
          return;
        }

        // 3. Establish Session (handled by store with correct signing per device)
        const success = await useE2EEStore.getState().establishSession(otherUser._id, publicKeys);

        if (success) {
          toast.success("Đã thiết lập mã hóa E2EE 🔒");
        } else {
          toast.error("Không thể tạo session key");
        }
      } else if (selectedConvo.type === "group") {
        // Group chat E2EE
        const participantIds = selectedConvo.participants.map((p) => String(p._id));

        // Check if E2EE is properly initialized
        const e2eeState = useE2EEStore.getState();
        if (!e2eeState.isInitialized) {
          toast.error("E2EE chưa được khởi tạo. Vui lòng đăng nhập lại và nhập PIN.");
          return;
        }
        if (!e2eeState._tempPin) {
          toast.error("Không có PIN. Vui lòng đăng nhập lại và nhập PIN.");
          return;
        }

        // Check if there are already encrypted messages we can't decrypt
        // This means someone else has already initiated E2EE with a different key
        const chatStore = useChatStore.getState();
        const messages = chatStore.messages[selectedConvo._id]?.items || [];
        const hasUndecryptableE2EE = messages.some(m => m.decryptionFailed === true);

        if (hasUndecryptableE2EE) {
          toast.error(
            "Nhóm này đã có tin nhắn E2EE từ người khác. " +
            "Bạn cần nhận key từ người đã bật E2EE. " +
            "Nếu không thể, hãy yêu cầu họ bật lại E2EE.",
            { duration: 8000 }
          );
          return;
        }

        // Get current key version from store (or start with 1)
        const currentVersion = e2eeState.currentGroupKeyVersion[selectedConvo._id] || 0;
        const newKeyVersion = currentVersion + 1; // New version is current + 1

        console.log("[E2EE] Starting group key exchange:", {
          conversationId: selectedConvo._id,
          participantCount: participantIds.length,
          newKeyVersion,
        });

        // Initiate group key exchange with specific keyVersion
        const success = await initiateGroupKeyExchange(selectedConvo._id, participantIds, newKeyVersion);

        if (success) {
          toast.success(`Đã thiết lập mã hóa E2EE cho nhóm 🔒 (key v${newKeyVersion})`);
        } else {
          toast.error(
            "Không thể thiết lập E2EE cho nhóm. " +
            "Các thành viên khác cần đăng nhập và nhập PIN trước.",
            { duration: 6000 }
          );
        }
      }
    } catch (error) {
      console.error("[E2EE] Failed to initialize session:", error);
      toast.error("Không thể thiết lập mã hóa E2EE");
    } finally {
      setIsEstablishingE2EE(false);
    }
  };

  const sendMessage = async () => {
    if (!value.trim()) return;
    const currentValue = value;
    setValue("");

    try {
      if (selectedConvo.type === "direct") {
        const otherUser = getOtherUser();
        if (!otherUser) return;

        // Check if E2EE is enabled
        if (isE2EEEnabled) {
          // Encrypt message with AES session key (returns ciphertext and counter)
          const encryptResult = await encryptMessage(otherUser._id, currentValue.trim());
          if (encryptResult) {
            // Send ENCRYPTED content with E2EE flag
            // Format: "E2EE:" prefix + base64 ciphertext
            const encryptedContent = `E2EE:${encryptResult.ciphertext}`;
            // Pass originalContent (plaintext) so sender can see it immediately
            // Pass counter for anti-replay protection
            await sendDirectMessage(otherUser._id, encryptedContent, undefined, currentValue.trim(), encryptResult.counter);
          } else {
            toast.error("Không thể mã hóa tin nhắn");
            return;
          }
        } else {
          // Send plaintext (no E2EE)
          await sendDirectMessage(otherUser._id, currentValue.trim());
        }
      } else if (selectedConvo.type === "group") {
        // Group chat
        if (isGroupE2EEEnabled) {
          // Encrypt group message with group session key
          // Returns { ciphertext, keyVersion } or null
          const encryptResult = await encryptGroupMessage(selectedConvo._id, currentValue.trim());
          if (encryptResult) {
            // Send ENCRYPTED content with E2EE flag
            const encryptedContent = `E2EE:${encryptResult.ciphertext}`;
            // Pass originalContent (plaintext) so sender can see it immediately
            // keyVersion is sent by useChatStore.sendGroupMessage based on currentGroupKeyVersion
            await sendGroupMessage(selectedConvo._id, encryptedContent, undefined, currentValue.trim());
          } else {
            toast.error("Không thể mã hóa tin nhắn nhóm");
            return;
          }
        } else {
          // Send plaintext (no E2EE)
          await sendGroupMessage(selectedConvo._id, currentValue.trim());
        }
      }
    } catch (error) {
      console.error("Lỗi khi gửi tin nhắn:", error);
      toast.error("Không thể gửi tin nhắn. Vui lòng thử lại sau.");
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const handleRekey = async () => {
    if (selectedConvo.type === "direct" && otherUser) {
      if (confirm("Bạn có chắc chắn muốn tạo lại khóa bảo mật? Hành động này sẽ cập nhật khóa trên tất cả thiết bị của đối phương.")) {
        setIsEstablishingE2EE(true);
        try {
          const success = await rekeyDirectChat(otherUser._id);
          if (success) toast.success("Đã làm mới khóa bảo mật thành công!");
          else toast.error("Không thể làm mới khóa bảo mật.");
        } finally {
          setIsEstablishingE2EE(false);
        }
      }
    } else if (selectedConvo.type === "group") {
      // Double-check: only owner can re-key group
      if (!isGroupOwner) {
        toast.error("Chỉ chủ nhóm mới có thể re-key nhóm");
        return;
      }

      if (confirm("Bạn có chắc chắn muốn tạo lại khóa bảo mật cho nhóm? Hành động này sẽ tạo phiên bản khóa mới (v" +
        ((useE2EEStore.getState().currentGroupKeyVersion[selectedConvo._id] || 0) + 1) + ") và gửi cho tất cả thành viên.")) {

        setIsEstablishingE2EE(true);
        try {
          const participantIds = selectedConvo.participants.map((p) => String(p._id));
          const currentVersion = useE2EEStore.getState().currentGroupKeyVersion[selectedConvo._id] || 0;
          const newKeyVersion = currentVersion + 1;

          const success = await initiateGroupKeyExchange(selectedConvo._id, participantIds, newKeyVersion);
          if (success) toast.success(`Đã làm mới khóa nhóm (v${newKeyVersion}) thành công!`);
          else toast.error("Không thể làm mới khóa nhóm.");
        } finally {
          setIsEstablishingE2EE(false);
        }
      }
    }
  };

  const handleDeleteSession = async () => {
    // Only allow delete session for direct chats, not group chats
    if (selectedConvo.type === "direct" && otherUser) {
      if (confirm("Bạn có chắc chắn muốn TẮT mã hóa E2EE? Tin nhắn sau này sẽ không được bảo vệ đầu cuối.")) {
        await deleteSession(otherUser._id);
        toast.info("Đã tắt mã hóa E2EE cho cuộc trò chuyện này.");
      }
    }
  };

  return (
    <div className="flex items-center gap-2 p-3 min-h-[56px] bg-background">
      <Button variant="ghost" size="icon" className="hover:bg-primary/10 transition-smooth">
        <ImagePlus className="size-4"></ImagePlus>
      </Button>

      {/* E2EE Status Indicator & Controls */}
      {e2eeInitialized && hasDropdownOptions && (
        <DropdownMenu>
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className={`transition-smooth ${isE2EEEnabled ? "text-green-500" : "text-muted-foreground"}`}
                    disabled={isEstablishingE2EE}
                  >
                    {isEstablishingE2EE ? (
                      <RefreshCw className="size-4 animate-spin" />
                    ) : isE2EEEnabled ? (
                      <Lock className="size-4" />
                    ) : (
                      <LockOpen className="size-4" />
                    )}
                  </Button>
                </DropdownMenuTrigger>
              </TooltipTrigger>
              <TooltipContent>
                {isEstablishingE2EE
                  ? "Đang thiết lập..."
                  : isE2EEEnabled
                    ? "Đã bảo vệ E2EE (Nhấn để quản lý)"
                    : "E2EE đang tắt (Nhấn để bật)"
                }
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>

          <DropdownMenuContent align="start">
            {!isE2EEEnabled ? (
              <DropdownMenuItem onClick={initializeE2EESession}>
                <Lock className="size-4 mr-2" />
                Bật mã hóa E2EE
              </DropdownMenuItem>
            ) : (
              <>
                {/* Only show re-key for direct chats or group owners */}
                {(selectedConvo.type === "direct" || isGroupOwner) && (
                  <DropdownMenuItem onClick={handleRekey}>
                    <RefreshCw className="size-4 mr-2" />
                    Làm mới khóa (Re-key)
                  </DropdownMenuItem>
                )}
                {/* Only show delete session for direct chats, not group chats */}
                {selectedConvo.type === "direct" && (
                  <DropdownMenuItem onClick={handleDeleteSession} className="text-red-500 focus:text-red-600">
                    <LockOpen className="size-4 mr-2" />
                    Tắt mã hóa (Xóa session)
                  </DropdownMenuItem>
                )}
              </>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      )}

      <div className="flex-1 relative">
        <Input
          onKeyDown={handleKeyPress}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={isE2EEEnabled ? "Nhập tin nhắn mã hóa..." : "Nhập tin nhắn..."}
          className={`pr-20 h-9 border-border/50 focus:border-primary/50 transition-smooth resize-none ${isE2EEEnabled ? "bg-green-50 dark:bg-green-950/20" : "bg-white dark:bg-background"
            }`}
        >
        </Input>

        <div className="absolute right-2 top-1/2 transform -translate-y-1/2 flex items-center gap-1">
          <Button
            asChild
            variant="ghost"
            size="icon"
            className="size-8 hover:bg-primary/10 transition-smooth"
          >
            <div>
              <EmojiPicker onchange={(emoji: string) => setValue(`${value}${emoji}`)} />
            </div>
          </Button>
        </div>
      </div>
      <Button
        onClick={sendMessage}
        className={`transition-smooth hover:scale-105 ${isE2EEEnabled
          ? "bg-green-600 hover:bg-green-700 hover:shadow-green-500/30"
          : "bg-gradient-chat hover:shadow-glow"
          }`}
        disabled={!value.trim()}
      >
        <Send className="size-4 text-white" />
        {isE2EEEnabled && <Lock className="size-3 text-white ml-1" />}
      </Button>
    </div>
  )
}

export default MessageInput