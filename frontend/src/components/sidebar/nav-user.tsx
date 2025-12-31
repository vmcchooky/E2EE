import {
  Bell,
  ChevronsUpDown,
  UserIcon,
} from "lucide-react"

import {
  Avatar,
  AvatarFallback,
  AvatarImage,
} from "@/components/ui/avatar"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar"

import type { User } from "@/types/user"
import Logout from "../auth/logout"
import { useState } from "react"
import ProfileDialog from "../profile/ProfileDialog"
import FriendRequestDialog from "../friendRequest/FriendRequestDialog"

export function NavUser({
  user,
}: {
  user: User
}) {
  const { isMobile } = useSidebar()
  const [friendRequestOpen, setfriendRequestOpen] = useState(false);
  const [openProfile, setOpenProfile] = useState(false)
  const fallbackInitial = (
    user.displayName ||
    user.firstname ||
    user.username ||
    user.email ||
    "?"
  )
    .charAt(0)
    .toUpperCase()

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton
              size="lg"
              className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
            >
              <Avatar className="h-8 w-8 rounded-lg">
                <AvatarImage src={user.avatarUrl} alt={user.displayName} />
                <AvatarFallback className="rounded-lg">{fallbackInitial}</AvatarFallback>
              </Avatar>
              <div className="grid flex-1 text-left text-sm leading-tight">
                <span className="truncate font-medium">{user.username}</span>
                <span className="truncate text-xs">{user.email}</span>
              </div>
              <ChevronsUpDown className="ml-auto size-4" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent
            className="w-(--radix-dropdown-menu-trigger-width) min-w-56 rounded-lg"
            side={isMobile ? "bottom" : "right"}
            align="end"
            sideOffset={4}
          >
            <DropdownMenuLabel className="p-0 font-normal">
              <div className="flex items-center gap-2 px-1 py-1.5 text-left text-sm">
                <Avatar className="h-8 w-8 rounded-lg">
                  <AvatarImage src={user.avatarUrl} alt={user.displayName} />
                  <AvatarFallback className="rounded-lg">{fallbackInitial}</AvatarFallback>
                </Avatar>
                <div className="grid flex-1 text-left text-sm leading-tight">
                  <span className="truncate font-medium">{user.username}</span>
                  <span className="truncate text-xs">{user.email}</span>
                </div>
              </div>
            </DropdownMenuLabel>
            <DropdownMenuGroup>
              <DropdownMenuItem onClick={() => setOpenProfile(true)}>
                <UserIcon className="text-muted-foreground dark:group-focus:!text-accent-foreground" />
                Tài khoản
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setfriendRequestOpen(true)}>
                <Bell className="text-muted-foreground dark:group-focus:!text-accent-foreground" />
                Thông báo
              </DropdownMenuItem>
            </DropdownMenuGroup>
            <DropdownMenuSeparator />
            <DropdownMenuItem className="cursor-pointer" variant="destructive">
              <Logout />
              Log out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        
        <ProfileDialog open={openProfile} setOpen={setOpenProfile} />
        <FriendRequestDialog open={friendRequestOpen} setOpen={setfriendRequestOpen} />
      </SidebarMenuItem>
    </SidebarMenu>
  )
}
