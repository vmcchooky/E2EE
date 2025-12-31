/**
 * FingerprintDialog - Hiển thị và xác minh fingerprint
 */

import { useState } from "react";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { useE2EEStore } from "@/stores/useE2EEStore";
import { useAuthStore } from "@/stores/useAuthStore";
import { Shield, Copy, Check, User, Lock } from "lucide-react";
import { toast } from "sonner";

interface FingerprintDialogProps {
    userId?: string;
    username?: string;
    children?: React.ReactNode;
}

const FingerprintDialog = ({ userId, username, children }: FingerprintDialogProps) => {
    const [copied, setCopied] = useState<"my" | "other" | null>(null);
    const { user } = useAuthStore();

    // Subscribe trực tiếp đến state để component re-render khi state thay đổi
    const myFingerprint = useE2EEStore((state) => state.myFingerprint);
    const userE2EEInfo = useE2EEStore((state) => state.userE2EEInfo);
    const getFormattedFingerprint = useE2EEStore((state) => state.getFormattedFingerprint);

    // Lấy fingerprint từ userE2EEInfo (reactive - sẽ cập nhật khi state thay đổi)
    const otherFingerprint = userId ? userE2EEInfo[userId]?.fingerprint || null : null;
    const hasSession = userId ? userE2EEInfo[userId]?.isEstablished || false : false;

    const copyToClipboard = async (text: string, type: "my" | "other") => {
        try {
            await navigator.clipboard.writeText(text);
            setCopied(type);
            toast.success("Đã copy fingerprint!");
            setTimeout(() => setCopied(null), 2000);
        } catch {
            toast.error("Không thể copy");
        }
    };

    return (
        <Dialog>
            <DialogTrigger asChild>
                {children || (
                    <Button variant="ghost" size="sm">
                        <Shield className="size-4 mr-1" />
                        Fingerprint
                    </Button>
                )}
            </DialogTrigger>
            <DialogContent className="sm:max-w-md">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        <Shield className="size-5 text-primary" />
                        Xác minh mã hóa E2EE
                    </DialogTitle>
                    <DialogDescription>
                        So sánh fingerprint qua kênh khác (điện thoại, gặp trực tiếp) để đảm bảo an toàn.
                    </DialogDescription>
                </DialogHeader>

                <div className="space-y-4 py-4">
                    {/* My Fingerprint */}
                    <div className="space-y-2">
                        <div className="flex items-center gap-2 text-sm font-medium">
                            <User className="size-4" />
                            Fingerprint của bạn ({user?.username})
                        </div>
                        <div className="flex items-center gap-2">
                            <code className="flex-1 bg-muted p-3 rounded-md font-mono text-sm tracking-wider">
                                {myFingerprint ? getFormattedFingerprint(myFingerprint) : "Chưa có"}
                            </code>
                            {myFingerprint && (
                                <Button
                                    variant="outline"
                                    size="icon"
                                    onClick={() => copyToClipboard(myFingerprint, "my")}
                                >
                                    {copied === "my" ? (
                                        <Check className="size-4 text-green-500" />
                                    ) : (
                                        <Copy className="size-4" />
                                    )}
                                </Button>
                            )}
                        </div>
                    </div>

                    {/* Other User's Fingerprint */}
                    {userId && username && (
                        <>
                            <div className="border-t my-4" />
                            <div className="space-y-2">
                                <div className="flex items-center gap-2 text-sm font-medium">
                                    <User className="size-4" />
                                    Fingerprint của {username}
                                    {hasSession && (
                                        <span className="inline-flex items-center gap-1 text-xs text-green-600 bg-green-100 dark:bg-green-900/30 px-2 py-0.5 rounded-full">
                                            <Lock className="size-3" />
                                            E2EE đang hoạt động
                                        </span>
                                    )}
                                </div>
                                <div className="flex items-center gap-2">
                                    <code className={`flex-1 p-3 rounded-md font-mono text-sm tracking-wider ${otherFingerprint
                                        ? "bg-muted"
                                        : "bg-yellow-50 dark:bg-yellow-900/20 text-yellow-600"
                                        }`}>
                                        {otherFingerprint
                                            ? getFormattedFingerprint(otherFingerprint)
                                            : "Chưa có public key"
                                        }
                                    </code>
                                    {otherFingerprint && (
                                        <Button
                                            variant="outline"
                                            size="icon"
                                            onClick={() => copyToClipboard(otherFingerprint, "other")}
                                        >
                                            {copied === "other" ? (
                                                <Check className="size-4 text-green-500" />
                                            ) : (
                                                <Copy className="size-4" />
                                            )}
                                        </Button>
                                    )}
                                </div>
                            </div>
                        </>
                    )}

                    {/* Instructions */}
                    <div className="bg-blue-50 dark:bg-blue-900/20 p-3 rounded-md text-sm text-blue-700 dark:text-blue-300">
                        <p className="font-medium mb-1">💡 Cách xác minh:</p>
                        <ol className="list-decimal list-inside space-y-1 text-xs">
                            <li>Liên hệ người kia qua điện thoại hoặc gặp trực tiếp</li>
                            <li>Đọc fingerprint của bạn cho họ nghe</li>
                            <li>So sánh với fingerprint họ thấy trên màn hình</li>
                            <li>Nếu khớp = an toàn, không khớp = có thể bị tấn công!</li>
                        </ol>
                    </div>
                </div>
            </DialogContent>
        </Dialog>
    );
};

export default FingerprintDialog;
