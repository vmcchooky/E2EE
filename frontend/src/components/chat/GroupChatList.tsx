import { useChatStore } from "@/stores/useChatStore"
import GroupChatCard from "./GroupChatCard";
const GroupChatList = () => {
    const { conversations } = useChatStore();

    if(!conversations || conversations.length === 0){
        return;
    }
    const groupConversations = conversations.filter((convo) => convo.type === "group");

    return (
        <div className="flex-1 overflow-y-auto p-2 space-y-2">
            {
                groupConversations.map((convo) => (
                    <GroupChatCard convo={convo} key={convo._id}/>
                ))
            }
        </div>
    )
}

export default GroupChatList