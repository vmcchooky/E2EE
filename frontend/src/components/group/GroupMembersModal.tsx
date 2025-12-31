import { useState } from "react";
import { useAuthStore } from "@/stores/useAuthStore";
import { useSocketStore } from "@/stores/useSocketStore";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
} from "../ui/dialog";
import { Button } from "../ui/button";
import { Card } from "../ui/card";
import { Users, Crown, LogOut } from "lucide-react";
import type { Conversation, Participant } from "@/types/chat";
import UserAvatar from "../chat/UserAvatar";
import StatusBadge from "../chat/StatusBadge";
import { toast } from "sonner";

interface GroupMembersModalProps {
    conversation: Conversation;
    open: boolean;
    onOpenChange: (open: boolean) => void;
}

const GroupMembersModal = ({ conversation, open, onOpenChange }: GroupMembersModalProps) => {
    const { user } = useAuthStore();
    const { onlineUsers } = useSocketStore();
    const [isRemoving, setIsRemoving] = useState<string | null>(null);

    if (!conversation || conversation.type !== "group") {
        return null;
    }

    const isOwner = conversation.group?.createdBy === user?._id;
    const participants = conversation.participants || [];

    // Sort participants: owner first, then others
    const sortedParticipants = [...participants].sort((a, b) => {
        if (a._id === conversation.group?.createdBy) return -1;
        if (b._id === conversation.group?.createdBy) return 1;
        return 0;
    });

    const handleRemoveMember = async (memberId: string, memberName: string) => {
        if (!isOwner) return;
        if (memberId === user?._id) {
            toast.error("Bạn không thể xóa chính mình khỏi nhóm");
            return;
        }
        if (memberId === conversation.group?.createdBy) {
            toast.error("Không thể xóa chủ nhóm");
            return;
        }

        if (!window.confirm(`Bạn có chắc chắn muốn xóa ${memberName} khỏi nhóm không?`)) {
            return;
        }

        setIsRemoving(memberId);
        try {
            // TODO: Implement remove member API
            toast.error("Tính năng xóa thành viên chưa được triển khai");
        } catch (error: any) {
            const errorMessage =
                error?.response?.data?.message ||
                error?.response?.data?.detail ||
                "Không thể xóa thành viên";
            toast.error(errorMessage);
        } finally {
            setIsRemoving(null);
        }
    };

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="glass max-w-md max-h-[80vh] flex flex-col">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2 text-xl capitalize">
                        <Users className="size-5" />
                        Thành viên nhóm ({participants.length})
                    </DialogTitle>
                    <DialogDescription>
                        Danh sách tất cả thành viên trong nhóm này
                    </DialogDescription>
                </DialogHeader>

                <div className="flex-1 overflow-y-auto space-y-2 mt-4">
                    {sortedParticipants.length > 0 ? (
                        sortedParticipants.map((participant: Participant) => {
                            const isParticipantOwner = participant._id === conversation.group?.createdBy;
                            const isOnline = onlineUsers.includes(participant._id);
                            const isCurrentUser = participant._id === user?._id;
                            const canRemove = isOwner && !isParticipantOwner && !isCurrentUser;

                            return (
                                <Card
                                    key={participant._id}
                                    className="p-3 hover:bg-muted/30 transition-colors"
                                >
                                    <div className="flex items-center gap-3">
                                        <div className="relative">
                                            <UserAvatar
                                                type="sidebar"
                                                name={participant.displayName || "Unknown"}
                                                avatarUrl={participant.avatarUrl || undefined}
                                            />
                                            <div className="absolute -bottom-1 -right-1">
                                                <StatusBadge
                                                    status={isOnline ? "online" : "offline"}
                                                />
                                            </div>
                                        </div>

                                        <div className="flex-1 min-w-0 flex flex-col">
                                            <div className="flex items-center gap-2">
                                                <h3 className="font-semibold text-sm truncate">
                                                    {participant.displayName || "Unknown"}
                                                    {isCurrentUser && " (Bạn)"}
                                                </h3>
                                                {isParticipantOwner && (
                                                    <Crown className="size-4 text-yellow-500" />
                                                )}
                                            </div>
                                            <span className="text-xs text-muted-foreground">
                                                {isOnline ? "Đang hoạt động" : "Không hoạt động"}
                                            </span>
                                        </div>

                                        {canRemove && (
                                            <Button
                                                variant="ghost"
                                                size="sm"
                                                className="text-destructive hover:text-destructive"
                                                onClick={() =>
                                                    handleRemoveMember(
                                                        participant._id,
                                                        participant.displayName || "Unknown"
                                                    )
                                                }
                                                disabled={isRemoving === participant._id}
                                            >
                                                <LogOut className="size-4" />
                                            </Button>
                                        )}
                                    </div>
                                </Card>
                            );
                        })
                    ) : (
                        <div className="text-center py-8 text-muted-foreground">
                            <Users className="size-12 mx-auto mb-3 opacity-50" />
                            <p>Chưa có thành viên</p>
                        </div>
                    )}
                </div>

                <div className="flex justify-end mt-4 pt-4 border-t">
                    <Button variant="outline" onClick={() => onOpenChange(false)}>
                        Đóng
                    </Button>
                </div>
            </DialogContent>
        </Dialog>
    );
};

export default GroupMembersModal;

