import { Button } from '../ui/button'
import { useAuthStore } from '@/stores/useAuthStore';
import { useNavigate } from 'react-router';
import { LogOut } from 'lucide-react';

const Logout = () => {
    const { logout } = useAuthStore();
    const navigate = useNavigate();


    const handleLogout = async () => {
        try {
            await logout();
            navigate("/login");
        } catch (error) {
            console.error("Đăng xuất thất bại", error);
        }
    }
    return (
        <Button variant="completeGhost" onClick={handleLogout}>
            <LogOut className='text-destructive'>Logout</LogOut>
        </Button>
    )
}

export default Logout