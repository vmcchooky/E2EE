import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface PINDialogProps {
  open: boolean;
  onConfirm: (pin: string) => void;
  onCancel?: () => void;
  title?: string;
  description?: string;
  error?: string;
}

export default function PINDialog({
  open,
  onConfirm,
  onCancel,
  title = "Nhập PIN mã hóa",
  description = "Vui lòng nhập PIN để giải mã khóa riêng E2EE",
  error,
}: PINDialogProps) {
  const [pin, setPin] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pin || pin.length < 4) return;

    setIsSubmitting(true);
    try {
      await onConfirm(pin);
      setPin(""); // Clear PIN after successful confirmation
    } catch (err) {
      console.error("PIN confirmation failed:", err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCancel = () => {
    setPin("");
    onCancel?.();
  };

  return (
    <Dialog open={open} onOpenChange={(open) => !open && handleCancel()}>
      <DialogContent className="sm:max-w-[425px]">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="pin">PIN</Label>
              <Input
                id="pin"
                type="password"
                placeholder="Nhập PIN (4-16 chữ số)"
                value={pin}
                onChange={(e) => {
                  // Only allow numbers
                  const value = e.target.value.replace(/[^0-9]/g, "");
                  if (value.length <= 16) {
                    setPin(value);
                  }
                }}
                maxLength={16}
                autoFocus
                disabled={isSubmitting}
              />
              {error && (
                <p className="text-sm text-destructive">{error}</p>
              )}
              <p className="text-xs text-muted-foreground">
                PIN được dùng để mã hóa khóa riêng E2EE của bạn
              </p>
            </div>
          </div>
          <DialogFooter>
            {onCancel && (
              <Button
                type="button"
                variant="outline"
                onClick={handleCancel}
                disabled={isSubmitting}
              >
                Hủy
              </Button>
            )}
            <Button
              type="submit"
              disabled={!pin || pin.length < 4 || isSubmitting}
            >
              {isSubmitting ? "Đang xử lý..." : "Xác nhận"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
