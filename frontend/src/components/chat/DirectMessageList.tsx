import { useChatStore } from "@/stores/useChatStore"
import DirectMessageCard from "./DirectMessageCard";


const DirectMessageList = () => {
    const { conversations } = useChatStore();

    if(!conversations || conversations.length === 0){
        return <div className="flex-1 flex items-center justify-center text-muted-foreground">
            No direct messages yet.
        </div>
    }
    const directConversations = conversations.filter((convo) => convo.type === "direct");

    return (
        <div className="flex-1 overflow-y-auto p-2 space-y-2">
            {
                directConversations.map((convo) => (
                <DirectMessageCard convo={convo} key={convo._id} />
                ))
            }
        </div>
    )
}

export default DirectMessageList