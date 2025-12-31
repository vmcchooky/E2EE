import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router";
import { useChatStore } from "@/stores/useChatStore";
import { useAuthStore } from "@/stores/useAuthStore";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { Users, Loader2 } from "lucide-react";
import { toast } from "sonner";

const JoinGroupPage = () => {
    const { inviteCode } = useParams<{ inviteCode: string }>();
    const navigate = useNavigate();
    const { accessToken, user, loading: authLoading, refreshToken } = useAuthStore();
    const { joinGroupViaInvite } = useChatStore();
    const [isJoining, setIsJoining] = useState(false);
    const [hasTriedAuth, setHasTriedAuth] = useState(false);

    const handleJoin = async () => {
        if (!inviteCode || isJoining) return;

        setIsJoining(true);
        try {
            const response: any = await joinGroupViaInvite(inviteCode);
            const message = response?.message || "Đã tham gia nhóm thành công!";

            // Check if user is already a member
            if (message.includes("đã là thành viên") || message.includes("already a member")) {
                toast.info(message);
            } else {
                toast.success(message);
            }

            // Navigate to home (will show the group conversation)
            navigate("/");
        } catch (error: any) {
            const errorMessage =
                error?.response?.data?.message ||
                error?.response?.data?.detail ||
                "Không thể tham gia nhóm";
            toast.error(errorMessage);
        } finally {
            setIsJoining(false);
        }
    };

    // Try to authenticate first if not logged in
    useEffect(() => {
        const tryAuth = async () => {
            if (accessToken && user) {
                setHasTriedAuth(true);
                return;
            }

            if (!hasTriedAuth && !authLoading) {
                setHasTriedAuth(true);
                try {
                    // Try to refresh token silently
                    await refreshToken(true);
                } catch (error) {
                    // Refresh failed, redirect to login
                    console.log("[JoinGroup] No valid refresh token, redirecting to login");
                    navigate("/login", {
                        state: {
                            returnTo: inviteCode ? `/join-group/${inviteCode}` : "/join-group"
                        }
                    });
                }
            }
        };

        tryAuth();
    }, [accessToken, user, authLoading, hasTriedAuth, refreshToken, navigate, inviteCode]);

    // Auto-join when authenticated and invite code is available
    useEffect(() => {
        // Wait for auth to complete
        if (authLoading || !hasTriedAuth) return;

        // If still no accessToken after trying auth, redirect to login
        if (!accessToken) {
            navigate("/login", {
                state: {
                    returnTo: inviteCode ? `/join-group/${inviteCode}` : "/join-group"
                }
            });
            return;
        }

        // Auto-join if invite code is provided and not already joining
        if (inviteCode && !isJoining) {
            handleJoin();
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [inviteCode, accessToken, authLoading, hasTriedAuth, isJoining, navigate]);

    const handleManualJoin = async (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        const formData = new FormData(e.currentTarget);
        const code = formData.get("code") as string;

        if (!code) {
            toast.error("Vui lòng nhập mã mời");
            return;
        }

        setIsJoining(true);
        try {
            const response = await joinGroupViaInvite(code);
            const message = response?.message || "Đã tham gia nhóm thành công!";

            // Check if user is already a member
            if (message.includes("đã là thành viên") || message.includes("already a member")) {
                toast.info(message);
            } else {
                toast.success(message);
            }

            // Navigate to home (will show the group conversation)
            navigate("/");
        } catch (error: any) {
            const errorMessage =
                error?.response?.data?.message ||
                error?.response?.data?.detail ||
                "Không thể tham gia nhóm";
            toast.error(errorMessage);
        } finally {
            setIsJoining(false);
        }
    };

    return (
        <div className="bg-muted flex min-h-svh flex-col items-center justify-center p-6 md:p-10 absolute inset-0 z-0 bg-gradient-purple">
            <Card className="w-full max-w-md">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-2xl">
                        <Users className="size-6" />
                        Tham gia nhóm chat
                    </CardTitle>
                    <CardDescription>
                        Nhập mã mời để tham gia vào nhóm chat
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    {inviteCode ? (
                        <div className="space-y-4">
                            <div className="text-center py-8">
                                {isJoining ? (
                                    <>
                                        <Loader2 className="size-12 mx-auto mb-4 animate-spin" />
                                        <p className="text-muted-foreground">
                                            Đang tham gia nhóm...
                                        </p>
                                    </>
                                ) : (
                                    <>
                                        <p className="text-sm text-muted-foreground mb-4">
                                            Mã mời: <code className="font-mono bg-muted px-2 py-1 rounded">{inviteCode}</code>
                                        </p>
                                        <Button onClick={handleJoin} disabled={isJoining}>
                                            Tham gia nhóm
                                        </Button>
                                    </>
                                )}
                            </div>
                        </div>
                    ) : (
                        <form onSubmit={handleManualJoin} className="space-y-4">
                            <div className="space-y-2">
                                <Label htmlFor="code">Mã mời</Label>
                                <Input
                                    id="code"
                                    name="code"
                                    placeholder="Nhập mã mời..."
                                    required
                                    disabled={isJoining}
                                />
                            </div>
                            <Button type="submit" className="w-full" disabled={isJoining}>
                                {isJoining ? (
                                    <>
                                        <Loader2 className="size-4 mr-2 animate-spin" />
                                        Đang tham gia...
                                    </>
                                ) : (
                                    "Tham gia nhóm"
                                )}
                            </Button>
                        </form>
                    )}
                </CardContent>
            </Card>
        </div>
    );
};

export default JoinGroupPage;

