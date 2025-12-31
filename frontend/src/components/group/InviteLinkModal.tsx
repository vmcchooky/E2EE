import { useState, useEffect } from "react";
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
import { Link2, Copy, Check } from "lucide-react";
import { toast } from "sonner";

interface InviteLinkModalProps {
    conversationId: string;
    open: boolean;
    onOpenChange: (open: boolean) => void;
}

const InviteLinkModal = ({ conversationId, open, onOpenChange }: InviteLinkModalProps) => {
    const createInviteLink = useChatStore((state) => state.createInviteLink);
    const [inviteCode, setInviteCode] = useState<string>("");
    const [inviteUrl, setInviteUrl] = useState<string>("");
    const [loading, setLoading] = useState(false);
    const [copied, setCopied] = useState(false);

    useEffect(() => {
        if (open && !inviteCode) {
            handleGenerateLink();
        }
    }, [open]);

    const handleGenerateLink = async () => {
        setLoading(true);
        try {
            const response = await createInviteLink(conversationId, 7); // 7 days expiry
            setInviteCode(response.invite_code);
            // Generate full URL
            const baseUrl = window.location.origin;
            setInviteUrl(`${baseUrl}${response.invite_url}`);
        } catch (error: any) {
            const errorMessage =
                error?.response?.data?.message ||
                error?.response?.data?.detail ||
                "Không thể tạo invite link";
            toast.error(errorMessage);
        } finally {
            setLoading(false);
        }
    };

    const handleCopyLink = async () => {
        try {
            await navigator.clipboard.writeText(inviteUrl);
            setCopied(true);
            toast.success("Đã sao chép link!");
            setTimeout(() => setCopied(false), 2000);
        } catch (error) {
            toast.error("Không thể sao chép link");
        }
    };

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="glass max-w-md">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2 text-xl capitalize">
                        <Link2 className="size-5" />
                        Mời thành viên qua link
                    </DialogTitle>
                    <DialogDescription>
                        Chia sẻ link này để mời người khác tham gia nhóm.
                    </DialogDescription>
                </DialogHeader>

                <div className="space-y-4">
                    {/* Invite code */}
                    <div className="space-y-2">
                        <Label>Mã mời</Label>
                        <div className="flex gap-2">
                            <Input
                                value={inviteCode}
                                readOnly
                                className="font-mono"
                                placeholder={loading ? "Đang tạo..." : "Nhấn để tạo link"}
                            />
                            <Button
                                type="button"
                                variant="outline"
                                onClick={handleGenerateLink}
                                disabled={loading}
                            >
                                {loading ? "Đang tạo..." : "Tạo mới"}
                            </Button>
                        </div>
                    </div>

                    {/* Invite URL */}
                    {inviteUrl && (
                        <div className="space-y-2">
                            <Label>Link mời</Label>
                            <div className="flex gap-2">
                                <Input
                                    value={inviteUrl}
                                    readOnly
                                    className="font-mono text-sm"
                                />
                                <Button
                                    type="button"
                                    variant="outline"
                                    onClick={handleCopyLink}
                                    className="gap-2"
                                >
                                    {copied ? (
                                        <>
                                            <Check className="size-4" />
                                            Đã copy
                                        </>
                                    ) : (
                                        <>
                                            <Copy className="size-4" />
                                            Copy
                                        </>
                                    )}
                                </Button>
                            </div>
                        </div>
                    )}

                    {/* Info */}
                    <div className="text-sm text-muted-foreground">
                        <p>• Link sẽ hết hạn sau 7 ngày</p>
                        <p>• Bất kỳ ai có link đều có thể tham gia nhóm</p>
                    </div>

                    {/* Close button */}
                    <div className="flex justify-end">
                        <Button variant="outline" onClick={() => onOpenChange(false)}>
                            Đóng
                        </Button>
                    </div>
                </div>
            </DialogContent>
        </Dialog>
    );
};

export default InviteLinkModal;

