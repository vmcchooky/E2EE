/**
 * KeyChangeWarningDialog - Cảnh báo khi public key thay đổi (MITM warning)
 */

import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { useE2EEStore } from "@/stores/useE2EEStore";
import { AlertTriangle, Shield, X } from "lucide-react";
import { e2eeService } from "@/services/e2eeService";
import { useState } from "react";

const KeyChangeWarningDialog = () => {
    const { keyChangeWarning, acceptNewKey, dismissKeyWarning, getFormattedFingerprint } = useE2EEStore();
    const [isAccepting, setIsAccepting] = useState(false);

    if (!keyChangeWarning) return null;

    const handleAccept = async () => {
        setIsAccepting(true);
        try {
            // Get the new public key from server
            const publicKeyResponse = await e2eeService.getUserPublicKey(keyChangeWarning.userId);
            if (publicKeyResponse) {
                await acceptNewKey(
                    keyChangeWarning.userId,
                    keyChangeWarning.username,
                    publicKeyResponse.public_key
                );
            }
        } catch (error) {
            console.error("[E2EE] Failed to accept new key:", error);
        } finally {
            setIsAccepting(false);
        }
    };

    return (
        <Dialog open={!!keyChangeWarning} onOpenChange={() => dismissKeyWarning()}>
            <DialogContent className="sm:max-w-lg">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2 text-red-600">
                        <AlertTriangle className="size-6" />
                        ⚠️ Cảnh báo bảo mật!
                    </DialogTitle>
                    <DialogDescription className="text-base">
                        Khóa công khai của <strong>{keyChangeWarning.username}</strong> đã thay đổi!
                    </DialogDescription>
                </DialogHeader>

                <div className="space-y-4 py-4">
                    {/* Warning explanation */}
                    <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-4 rounded-lg">
                        <p className="text-sm text-red-700 dark:text-red-300 mb-2">
                            Điều này có thể xảy ra khi:
                        </p>
                        <ul className="text-sm text-red-600 dark:text-red-400 list-disc list-inside space-y-1">
                            <li>Người dùng đổi thiết bị hoặc cài lại ứng dụng</li>
                            <li><strong className="text-red-700">Có ai đó đang cố gắng nghe lén (tấn công MITM)</strong></li>
                        </ul>
                    </div>

                    {/* Fingerprint comparison */}
                    <div className="space-y-3">
                        <div>
                            <p className="text-sm font-medium text-muted-foreground mb-1">Fingerprint cũ (đáng tin cậy):</p>
                            <code className="block bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300 p-2 rounded-md font-mono text-sm">
                                {getFormattedFingerprint(keyChangeWarning.oldFingerprint)}
                            </code>
                        </div>
                        <div>
                            <p className="text-sm font-medium text-muted-foreground mb-1">Fingerprint mới:</p>
                            <code className="block bg-yellow-50 dark:bg-yellow-900/20 text-yellow-700 dark:text-yellow-300 p-2 rounded-md font-mono text-sm">
                                {getFormattedFingerprint(keyChangeWarning.newFingerprint)}
                            </code>
                        </div>
                    </div>

                    {/* Instructions */}
                    <div className="bg-blue-50 dark:bg-blue-900/20 p-3 rounded-md text-sm text-blue-700 dark:text-blue-300">
                        <p className="font-medium mb-1">
                            <Shield className="size-4 inline mr-1" />
                            Cách xác minh:
                        </p>
                        <p className="text-xs">
                            Liên hệ <strong>{keyChangeWarning.username}</strong> qua kênh khác (gọi điện, gặp trực tiếp)
                            và hỏi xem họ có đổi thiết bị/cài lại ứng dụng không. Nếu <strong>KHÔNG</strong>,
                            đừng chấp nhận khóa mới!
                        </p>
                    </div>
                </div>

                <DialogFooter className="flex gap-2 sm:gap-0">
                    <Button
                        variant="outline"
                        onClick={async () => await dismissKeyWarning()}
                        className="flex-1 sm:flex-none"
                    >
                        <X className="size-4 mr-1" />
                        Từ chối & Giữ khóa cũ
                    </Button>
                    <Button
                        variant="destructive"
                        onClick={handleAccept}
                        disabled={isAccepting}
                        className="flex-1 sm:flex-none"
                    >
                        {isAccepting ? "Đang xử lý..." : "Chấp nhận khóa mới"}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
};

export default KeyChangeWarningDialog;

