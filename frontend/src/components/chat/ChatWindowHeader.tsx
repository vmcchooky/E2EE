import { useChatStore } from "@/stores/useChatStore";
import type { Conversation, Participant } from "@/types/chat"
import { SidebarTrigger } from "../ui/sidebar";
import { useAuthStore } from "@/stores/useAuthStore";
import { Separator } from "@radix-ui/react-separator";
import GroupChatAvatar from "./GroupChatAvatar";
import UserAvatar from "./UserAvatar";
import StatusBadge from "./StatusBadge";
import { useSocketStore } from "@/stores/useSocketStore";
import { useE2EEStore } from "@/stores/useE2EEStore";
import { Lock, Shield, UserPlus, Link2, LogOut, MoreVertical } from "lucide-react";
import { Badge } from "../ui/badge";
import FingerprintDialog from "../e2ee/FingerprintDialog";
import { Button } from "../ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "../ui/tooltip";
import { toast } from "sonner";
import { useState } from "react";
import AddMembersModal from "../group/AddMembersModal";
import InviteLinkModal from "../group/InviteLinkModal";

const ChatWindowHeader = ({ chat, onShowMembersPanel }: { chat?: Conversation; onShowMembersPanel?: () => void }) => {
    const { conversations, activeConversationId, leaveGroup } = useChatStore();
    const { user } = useAuthStore();
    const { onlineUsers } = useSocketStore();

    // Subscribe trực tiếp đến state để reactive khi E2EE status thay đổi
    const e2eeInitialized = useE2EEStore((state) => state.isInitialized);
    const userE2EEInfo = useE2EEStore((state) => state.userE2EEInfo);

    const [showAddMembersModal, setShowAddMembersModal] = useState(false);
    const [showInviteLinkModal, setShowInviteLinkModal] = useState(false);
    const [isLeaving, setIsLeaving] = useState(false);

    let otherUser: Participant | null = null;

    chat = chat ?? conversations.find((c) => c._id === activeConversationId);

    if (!chat) {
        return (
            <header className="md:hidden sticky top-0 z-10 flex items-center gap-2 px-4 py-2 w-full">
                <SidebarTrigger className="-ml-1 text-foreground" />
            </header>
        )
    }
    if (chat.type === "direct") {
        const otherUsers = chat.participants.filter((p) => p._id !== user?._id);
        otherUser = otherUsers.length > 0 ? otherUsers[0] : null;
        if (!user || !otherUser) return;
    }

    // Check E2EE status for direct chat (reactive)
    const isE2EEActive = chat.type === "direct" && otherUser &&
        (userE2EEInfo[otherUser._id]?.isEstablished || false);

    return (
        <header className="sticky top-0 z-10 px-4 py-2 flex items-center bg-background">
            <div className="flex items-center gap-2 w-full">
                <SidebarTrigger className="-ml-1 text-foreground" />
                <Separator orientation="vertical" className="mr-2 data-[orientation=vertical]:h-4" />
                <div className="p-2 w-full flex items-center gap-3">
                    {/* avatar */}
                    <div className="relative">
                        {chat.type === "direct" ? (
                            <>
                                <UserAvatar
                                    type={"sidebar"}
                                    name={otherUser?.displayName || "Moji"}
                                    avatarUrl={otherUser?.avatarUrl || undefined}
                                />
                                <StatusBadge status={
                                    onlineUsers.includes(otherUser?._id || "") ? "online" : "offline"
                                } />
                            </>
                        ) : (
                            <GroupChatAvatar
                                participants={chat.participants}
                                type="sidebar"
                            />
                        )}
                    </div>

                    {/* name and E2EE status */}
                    <div className="flex-1">
                        <div className="flex items-center gap-2">
                            <h2 className="font-semibold text-foreground">
                                {chat.type === "direct"
                                    ? otherUser?.displayName || "Unknown User"
                                    : chat.group?.name || "Unnamed Group Chat"}
                            </h2>

                            {/* Group owner badge */}
                            {chat.type === "group" && chat.group?.createdBy && (
                                <TooltipProvider>
                                    <Tooltip>
                                        <TooltipTrigger asChild>
                                            <Badge
                                                variant="outline"
                                                className="text-xs px-2 py-0.5 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 border-blue-300"
                                            >
                                                <Shield className="size-3 mr-1" />
                                                {chat.group.createdBy === user?._id
                                                    ? "Chủ nhóm"
                                                    : "Nhóm"}
                                            </Badge>
                                        </TooltipTrigger>
                                        <TooltipContent>
                                            {chat.group.createdBy === user?._id
                                                ? "Bạn là chủ nhóm"
                                                : "Bạn là thành viên của nhóm"}
                                        </TooltipContent>
                                    </Tooltip>
                                </TooltipProvider>
                            )}

                            {/* E2EE Status Badge */}
                            {chat.type === "direct" && e2eeInitialized && (
                                <TooltipProvider>
                                    <Tooltip>
                                        <TooltipTrigger asChild>
                                            <Badge
                                                variant="outline"
                                                className={`text-xs px-2 py-0.5 ${isE2EEActive
                                                    ? "bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 border-green-300"
                                                    : "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400 border-yellow-300"
                                                    }`}
                                            >
                                                <Lock className="size-3 mr-1" />
                                                {isE2EEActive ? "E2EE" : "Chưa mã hóa"}
                                            </Badge>
                                        </TooltipTrigger>
                                        <TooltipContent>
                                            {isE2EEActive
                                                ? "Cuộc trò chuyện được mã hóa đầu cuối"
                                                : "Nhấn nút khóa ở ô chat để bật mã hóa"
                                            }
                                        </TooltipContent>
                                    </Tooltip>
                                </TooltipProvider>
                            )}
                        </div>
                    </div>

                    {/* Fingerprint buttons for direct chat */}
                    {chat.type === "direct" && otherUser && e2eeInitialized && (
                        <div className="flex items-center gap-2">
                            {/* Fingerprint button */}
                            <FingerprintDialog
                                userId={otherUser._id}
                                username={otherUser.displayName || otherUser._id}
                            >
                                <Button variant="ghost" size="sm" className="gap-1">
                                    <Shield className="size-4" />
                                    <span className="hidden sm:inline">Fingerprint</span>
                                </Button>
                            </FingerprintDialog>
                        </div>
                    )}

                    {/* Group management buttons */}
                    {chat.type === "group" && (
                        <div className="flex items-center gap-2">
                            {/* Add members and invite link buttons - only for group owner */}
                            {chat.group?.createdBy === user?._id && (
                                <>
                                    <TooltipProvider>
                                        <Tooltip>
                                            <TooltipTrigger asChild>
                                                <Button
                                                    variant="ghost"
                                                    size="sm"
                                                    className="gap-1"
                                                    onClick={() => setShowAddMembersModal(true)}
                                                >
                                                    <UserPlus className="size-4" />
                                                    <span className="hidden sm:inline">Thêm thành viên</span>
                                                </Button>
                                            </TooltipTrigger>
                                            <TooltipContent>
                                                <p>Thêm bạn bè vào nhóm</p>
                                            </TooltipContent>
                                        </Tooltip>
                                    </TooltipProvider>

                                    <TooltipProvider>
                                        <Tooltip>
                                            <TooltipTrigger asChild>
                                                <Button
                                                    variant="ghost"
                                                    size="sm"
                                                    className="gap-1"
                                                    onClick={() => setShowInviteLinkModal(true)}
                                                >
                                                    <Link2 className="size-4" />
                                                    <span className="hidden sm:inline">Link mời</span>
                                                </Button>
                                            </TooltipTrigger>
                                            <TooltipContent>
                                                <p>Tạo link mời để chia sẻ</p>
                                            </TooltipContent>
                                        </Tooltip>
                                    </TooltipProvider>
                                </>
                            )}

                            {/* Three dots menu button - for all members */}
                            <TooltipProvider>
                                <Tooltip>
                                    <TooltipTrigger asChild>
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            className="gap-1"
                                            onClick={() => onShowMembersPanel?.()}
                                        >
                                            <MoreVertical className="size-4" />
                                        </Button>
                                    </TooltipTrigger>
                                    <TooltipContent>
                                        <p>Xem danh sách thành viên</p>
                                    </TooltipContent>
                                </Tooltip>
                            </TooltipProvider>
                        </div>
                    )}

                    {/* Leave group button for all group members */}
                    {chat.type === "group" && (
                        <div className="flex items-center gap-2">
                            <TooltipProvider>
                                <Tooltip>
                                    <TooltipTrigger asChild>
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            className="gap-1 text-destructive hover:text-destructive"
                                            onClick={async () => {
                                                if (!chat._id) return;
                                                if (window.confirm("Bạn có chắc chắn muốn rời nhóm này không?")) {
                                                    setIsLeaving(true);
                                                    try {
                                                        await leaveGroup(chat._id);
                                                        toast.success("Đã rời nhóm thành công");
                                                    } catch (error: any) {
                                                        const errorMessage =
                                                            error?.response?.data?.message ||
                                                            error?.response?.data?.detail ||
                                                            "Không thể rời nhóm";
                                                        toast.error(errorMessage);
                                                    } finally {
                                                        setIsLeaving(false);
                                                    }
                                                }
                                            }}
                                            disabled={isLeaving}
                                        >
                                            <LogOut className={`size-4 ${isLeaving ? "animate-pulse" : ""}`} />
                                            <span className="hidden sm:inline">
                                                {isLeaving ? "Đang rời..." : "Rời nhóm"}
                                            </span>
                                        </Button>
                                    </TooltipTrigger>
                                    <TooltipContent>
                                        <p>Rời khỏi nhóm chat này</p>
                                    </TooltipContent>
                                </Tooltip>
                            </TooltipProvider>
                        </div>
                    )}
                </div>
            </div>

            {/* Modals */}
            {chat.type === "group" && (
                <>
                    <AddMembersModal
                        conversationId={chat._id}
                        open={showAddMembersModal}
                        onOpenChange={setShowAddMembersModal}
                    />
                    <InviteLinkModal
                        conversationId={chat._id}
                        open={showInviteLinkModal}
                        onOpenChange={setShowInviteLinkModal}
                    />
                </>
            )}
        </header>
    )
}

export default ChatWindowHeader