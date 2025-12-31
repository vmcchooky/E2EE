import { useState, useEffect, useRef } from "react";
import { useFriendStore } from "@/stores/useFriendStore";
import { useChatStore } from "@/stores/useChatStore";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
} from "../ui/dialog";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import { Card } from "../ui/card";
import { UserPlus, Users, X } from "lucide-react";
import type { Friend } from "@/types/user";
import UserAvatar from "../chat/UserAvatar";
import { toast } from "sonner";

interface AddMembersModalProps {
    conversationId: string;
    open: boolean;
    onOpenChange: (open: boolean) => void;
}

const AddMembersModal = ({ conversationId, open, onOpenChange }: AddMembersModalProps) => {
    const friends = useFriendStore((state) => state.friends) || [];
    const getFriends = useFriendStore((state) => state.getFriends);
    const addMembersToGroup = useChatStore((state) => state.addMembersToGroup);
    const conversations = useChatStore((state) => state.conversations);
    const [search, setSearch] = useState("");
    const [selectedFriends, setSelectedFriends] = useState<Friend[]>([]);
    const [loading, setLoading] = useState(false);
    const hasFetchedRef = useRef(false);

    // Get current group's participants
    const currentGroup = conversations.find((c) => c._id === conversationId);
    const existingMemberIds = currentGroup?.participants?.map((p) => p._id) || [];

    useEffect(() => {
        if (open && friends.length === 0 && !hasFetchedRef.current) {
            hasFetchedRef.current = true;
            void getFriends();
        }
        if (friends.length > 0) {
            hasFetchedRef.current = false;
        }
    }, [open, friends.length, getFriends]);

    // Reset when modal closes
    useEffect(() => {
        if (!open) {
            setSearch("");
            setSelectedFriends([]);
        }
    }, [open]);

    // Filter out friends who are already members of the group
    const filteredFriends = friends.filter(
        (friend) =>
            friend.displayName?.toLowerCase().includes(search.toLowerCase()) &&
            !selectedFriends.some((f) => f._id === friend._id) &&
            !existingMemberIds.includes(friend._id) // Exclude existing members
    );

    // Friends who are already members (for display info)
    const alreadyMembers = friends.filter((friend) =>
        existingMemberIds.includes(friend._id)
    );

    const handleSelectFriend = (friend: Friend) => {
        setSelectedFriends([...selectedFriends, friend]);
        setSearch("");
    };

    const handleRemoveFriend = (friend: Friend) => {
        setSelectedFriends(selectedFriends.filter((f) => f._id !== friend._id));
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (selectedFriends.length === 0) {
            toast.warning("Vui lòng chọn ít nhất 1 người bạn để thêm vào nhóm");
            return;
        }

        setLoading(true);
        try {
            const response: any = await addMembersToGroup(
                conversationId,
                selectedFriends.map((f) => f._id)
            );

            if (response?.data) {
                const { added_count, already_members_count, message } = response.data;

                if (already_members_count > 0 && added_count > 0) {
                    toast.warning(message || `Đã thêm ${added_count} thành viên (${already_members_count} người đã là thành viên)`);
                } else if (already_members_count > 0 && added_count === 0) {
                    toast.warning(message || "Tất cả người dùng đã là thành viên của nhóm");
                } else {
                    toast.success(message || `Đã thêm ${added_count} thành viên vào nhóm`);
                }
            } else {
                toast.success(`Đã thêm ${selectedFriends.length} thành viên vào nhóm`);
            }

            onOpenChange(false);
        } catch (error: any) {
            const errorMessage =
                error?.response?.data?.message ||
                error?.response?.data?.detail ||
                "Không thể thêm thành viên vào nhóm";

            // Check if it's a warning case (all already members)
            if (error?.response?.status === 200 || error?.response?.data?.already_members) {
                toast.warning(errorMessage);
            } else {
                toast.error(errorMessage);
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="glass max-w-md">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2 text-xl capitalize">
                        <UserPlus className="size-5" />
                        Thêm thành viên vào nhóm
                    </DialogTitle>
                    <DialogDescription>
                        Chọn bạn bè để thêm vào nhóm chat này.
                        {alreadyMembers.length > 0 && (
                            <span className="block mt-1 text-xs text-muted-foreground">
                                {alreadyMembers.length} bạn bè đã là thành viên của nhóm
                            </span>
                        )}
                    </DialogDescription>
                </DialogHeader>

                <form onSubmit={handleSubmit} className="space-y-4">
                    {/* Search input */}
                    <div className="space-y-2">
                        <Label htmlFor="search">Tìm bạn bè</Label>
                        <Input
                            id="search"
                            placeholder="Tìm theo tên hiển thị..."
                            value={search}
                            onChange={(e) => setSearch(e.target.value)}
                        />
                    </div>

                    {/* Selected friends */}
                    {selectedFriends.length > 0 && (
                        <div className="space-y-2">
                            <Label>Đã chọn ({selectedFriends.length})</Label>
                            <div className="flex flex-wrap gap-2">
                                {selectedFriends.map((friend) => (
                                    <Card
                                        key={friend._id}
                                        className="p-2 flex items-center gap-2"
                                    >
                                        <UserAvatar
                                            type="sidebar"
                                            name={friend.displayName || "User"}
                                            avatarUrl={friend.avatarUrl || undefined}
                                        />
                                        <span className="text-sm font-medium">
                                            {friend.displayName}
                                        </span>
                                        <Button
                                            type="button"
                                            variant="ghost"
                                            size="sm"
                                            className="h-6 w-6 p-0"
                                            onClick={() => handleRemoveFriend(friend)}
                                        >
                                            <X className="size-4" />
                                        </Button>
                                    </Card>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Friends list */}
                    <div className="space-y-2">
                        <Label>Danh sách bạn bè</Label>
                        <div className="space-y-2 max-h-60 overflow-y-auto">
                            {filteredFriends.length > 0 ? (
                                filteredFriends.map((friend) => (
                                    <Card
                                        key={friend._id}
                                        onClick={() => handleSelectFriend(friend)}
                                        className="p-3 cursor-pointer transition-smooth hover:shadow-soft glass hover:bg-muted/30 group/friendCard"
                                    >
                                        <div className="flex items-center gap-3">
                                            <UserAvatar
                                                type="sidebar"
                                                name={friend.displayName || "User"}
                                                avatarUrl={friend.avatarUrl || undefined}
                                            />
                                            <div className="flex-1 min-w-0 flex flex-col">
                                                <h2 className="font-semibold text-sm truncate">
                                                    {friend.displayName}
                                                </h2>
                                                <span className="text-sm text-muted-foreground">
                                                    @{friend.username}
                                                </span>
                                            </div>
                                            <UserPlus className="size-4 opacity-0 group-hover/friendCard:opacity-100 transition-opacity" />
                                        </div>
                                    </Card>
                                ))
                            ) : (
                                <div className="text-center py-8 text-muted-foreground">
                                    <Users className="size-12 mx-auto mb-3 opacity-50" />
                                    {search
                                        ? "Không tìm thấy bạn bè"
                                        : alreadyMembers.length > 0
                                            ? "Tất cả bạn bè đã là thành viên của nhóm"
                                            : "Chưa có bạn bè. Thêm bạn vô để mời!"}
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Submit button */}
                    <div className="flex justify-end gap-2">
                        <Button
                            type="button"
                            variant="outline"
                            onClick={() => onOpenChange(false)}
                        >
                            Hủy
                        </Button>
                        <Button type="submit" disabled={loading || selectedFriends.length === 0}>
                            {loading ? "Đang thêm..." : `Thêm ${selectedFriends.length} thành viên`}
                        </Button>
                    </div>
                </form>
            </DialogContent>
        </Dialog>
    );
};

export default AddMembersModal;

