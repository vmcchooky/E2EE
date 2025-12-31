import type React from "react";
import { Card } from "../ui/card"
import { formatOnlineTime, cn } from "@/lib/utils"
import { MoreHorizontal, Trash2 } from "lucide-react";
import { useState } from "react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "../ui/dropdown-menu"

interface ChatCardProps {
    convoId: string;
    name: string;
    timestamp?: Date;
    isActive: boolean;
    onSelect: (id: string) => void;
    onDelete?: (id: string) => void;
    unreadCount?: number;
    leftSection: React.ReactNode;
    subtitle?: React.ReactNode;

}

const ChatCard = (
    { convoId, name, timestamp, isActive, onSelect, onDelete, unreadCount, leftSection, subtitle }: ChatCardProps
) => {
    const [open, setOpen] = useState(false);

    const handleDelete = (e: React.MouseEvent) => {
        e.stopPropagation();
        if (onDelete) {
            onDelete(convoId);
        }
        setOpen(false);
    };

    return (
        <Card
            key={convoId}
            className={cn("border-none p-3 cursor-pointer transition-smooth glass hover:bg-muted/30", isActive && "ring-2 ring-primary/50 bg-gradient-to-r from-primary-glow/10 to-primary-foreground"

            )}
            onClick={() => onSelect(convoId)}
        >
            <div className="flex items-center gap-3">
                <div className="relative">{leftSection}</div>
                <div className="flex-1 min-w-0">
                    <div className="flex justify-between items-center mb-1">
                        <h3 className={cn("font-semibold text-sm truncate", unreadCount && unreadCount > 0 && "text-foreground")}>
                            {name}
                        </h3>
                        <span className="text-xs text-muted-foreground">{timestamp && formatOnlineTime(timestamp)}</span>
                    </div>
                    <div className="flex item-center justify-between">
                        <div className="flex item-center gap-1 flex-1 min-w-0">
                            <div className="flex items-center gap-1 flex-1 min-w-0">{subtitle}</div>
                            <DropdownMenu open={open} onOpenChange={setOpen}>
                                <DropdownMenuTrigger asChild onClick={(e) => e.stopPropagation()}>
                                    <MoreHorizontal className="size-4 text-muted-foreground opacity-0 group-hover:opacity-100 hover:size-5 transition-smooth cursor-pointer"></MoreHorizontal>
                                </DropdownMenuTrigger>
                                <DropdownMenuContent align="end">
                                    <DropdownMenuItem onClick={handleDelete} className="text-destructive">
                                        <Trash2 className="size-4 mr-2" />
                                        Xóa
                                    </DropdownMenuItem>
                                </DropdownMenuContent>
                            </DropdownMenu>
                        </div>
                    </div>
                </div>
            </div>
        </Card>
    )
}

export default ChatCard