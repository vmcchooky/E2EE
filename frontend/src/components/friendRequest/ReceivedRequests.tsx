import { useFriendStore } from "@/stores/useFriendStore";
import FriendRequestItem from "./FriendRequestItem";
import { Button } from "../ui/button";
import { toast } from "sonner";

const ReceivedRequests = () => {
  const { acceptRequest, declineRequest, loading, receivedList } = useFriendStore();

  console.log("ReceivedRequests - receivedList:", receivedList); // Debug log

  if (!receivedList || receivedList.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        Bạn chưa có lời mời kết bạn nào.
      </p>
    );
  }

  const handleAccept = async (requestId: string) => {
    try {
      console.log("Accepting request ID:", requestId); // Debug log
      await acceptRequest(requestId);
      toast.success("Đã đồng ý kết bạn thành công");
    } catch (error: any) {
      console.error("Error accepting request:", error);
      toast.error(error?.response?.data?.message || "Lỗi khi chấp nhận lời mời");
    }
  };

  const handleDecline = async (requestId: string) => {
    try {
      console.log("Declining request ID:", requestId); // Debug log
      await declineRequest(requestId);
      toast.info("Đã từ chối kết bạn");
    } catch (error: any) {
      console.error("Error declining request:", error);
      toast.error(error?.response?.data?.message || "Lỗi khi từ chối lời mời");
    }
  };

  return (
    <div className="space-y-3 mt-4">
      {receivedList.map((req, index) => {
        console.log("Request item:", req); // Debug log
        const requestId = req._id || `request-${index}`;

        return (
          <FriendRequestItem
            key={requestId}
            requestInfo={req}
            actions={
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => handleAccept(req._id)}
                  disabled={loading || !req._id}
                >
                  Chấp nhận
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => handleDecline(req._id)}
                  disabled={loading || !req._id}
                >
                  Từ chối
                </Button>
              </div>
            }
            type="received"
          />
        );
      })}
    </div>
  );
};

export default ReceivedRequests;
