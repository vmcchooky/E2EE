import { useEffect, useState, type Dispatch, type SetStateAction } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useFriendStore } from "@/stores/useFriendStore";
import SentRequests from "./SentRequests";
import ReceivedRequests from "./ReceivedRequests";

interface FriendRequestDialogProps {
  open: boolean;
  setOpen: Dispatch<SetStateAction<boolean>>;
}

const FriendRequestDialog = ({ open, setOpen }: FriendRequestDialogProps) => {
  const [tab, setTab] = useState("received");
  const { getAllFriendRequests, receivedList, sentList } = useFriendStore();

  useEffect(() => {
    if (open) {
      const loadRequest = async () => {
        try {
          console.log("Loading friend requests..."); // Debug log
          await getAllFriendRequests();
        } catch (error) {
          console.error("Lỗi xảy ra khi load requests", error);
        }
      };

      loadRequest();
    }
  }, [open, getAllFriendRequests]);

  useEffect(() => {
    console.log("Current state - Received:", receivedList, "Sent:", sentList);
  }, [receivedList, sentList]);

  return (
    <Dialog
      open={open}
      onOpenChange={setOpen}
    >
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Lời mời kết bạn</DialogTitle>
        </DialogHeader>
        <Tabs
          value={tab}
          onValueChange={setTab}
          className="w-full"
        >
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="received">Đã nhận ({receivedList.length})</TabsTrigger>
            <TabsTrigger value="sent">Đã gửi ({sentList.length})</TabsTrigger>
          </TabsList>

          <TabsContent value="received">
            <ReceivedRequests />
          </TabsContent>

          <TabsContent value="sent">
            <SentRequests />
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
};

export default FriendRequestDialog;
