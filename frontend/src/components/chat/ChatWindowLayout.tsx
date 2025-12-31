import { useChatStore } from "@/stores/useChatStore";
import ChatWelcomeScreen from "./ChatWelcomeScreen";
import ChatWindowSkeleton from "./ChatWindowSkeleton";
import { SidebarInset } from "../ui/sidebar";
import ChatWindowHeader from "./ChatWindowHeader";
import ChatWindowBody from "./ChatWindowBody";
import MessageInput from "./MessageInput";
import GroupMembersPanel from "../group/GroupMembersPanel";
import { useState } from "react";

const ChatWindowLayout = () => {
    const {
        activeConversationId,
        conversations,
        messageLoading,
        messages,
    } = useChatStore();

    const [showMembersPanel, setShowMembersPanel] = useState(false);

    const selectedConvo = conversations.find((c) => c._id === activeConversationId) ?? null;

    if(!selectedConvo){
        return <ChatWelcomeScreen />
    }

    if(messageLoading){
        return <ChatWindowSkeleton />
    }

    return (
        <>
            <SidebarInset className="flex flex-col h-full flex-1 overflow-hidden rounded-sm shadow-md relative">
                
                <ChatWindowHeader chat={selectedConvo} onShowMembersPanel={() => setShowMembersPanel(true)}/>

                <div className="flex-1 overflow-y-auto bg-primary-foreground">
                    <ChatWindowBody />
                </div>

                <MessageInput selectedConvo={selectedConvo}/>

            </SidebarInset>

            {/* Group Members Panel */}
            {selectedConvo.type === "group" && (
                <GroupMembersPanel
                    conversation={selectedConvo}
                    open={showMembersPanel}
                    onClose={() => setShowMembersPanel(false)}
                />
            )}
        </>
    )
}

export default ChatWindowLayout