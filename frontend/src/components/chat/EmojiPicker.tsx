import { useThemeStore } from "@/stores/useThemeStore";
import { Popover, PopoverContent, PopoverTrigger } from "../ui/popover";
import { Smile } from "lucide-react";
import Picker from '@emoji-mart/react';
import data from "@emoji-mart/data";



interface EmojiPickerProps {
    onchange: (value: string) => void;
}

const EmojiPicker = ({ onchange }: EmojiPickerProps) => {
    const { isDark } = useThemeStore();

    return (
        <Popover>
            <PopoverTrigger className="cursor-pointer">
                <Smile/>
            </PopoverTrigger>

            <PopoverContent side="right" sideOffset={40} className="bg-transparent border-none shadow-none drop-shadow-none mb-12">
                <Picker
                    data={data}
                    onEmojiSelect={(emoji: any) => onchange(emoji.native)}
                    theme={isDark ? "dark" : "light"}
                    emojiSize={24}
                />
            </PopoverContent>
        
        
        </Popover>
    )
}

export default EmojiPicker