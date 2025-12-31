import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Input } from "../ui/input"
import { Label } from "../ui/label"
import { z } from "zod"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { useAuthStore } from "@/stores/useAuthStore"
import { useNavigate } from "react-router"


const loginSchema = z.object({
  username: z.string().min(3, "Tên đăng nhập không được để trống"),
  password: z.string().min(6, "Mật khẩu không được để trống"),
})

type LoginFormValues = z.infer<typeof loginSchema>

export function LoginForm({
  className,
  returnTo = "/",
  ...props
}: React.ComponentProps<"div"> & { returnTo?: string }) {

  const { login } = useAuthStore();
  const navigate = useNavigate();

  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
  });

  const onSubmit = async (data: LoginFormValues) => {
    const { username, password } = data;
    await login(username, password);
    navigate(returnTo);
  }

  return (
    <div className={cn("flex flex-col gap-6", className)} {...props}>
      <Card className="overflow-hidden p-0">
        <CardContent className="grid p-0 md:grid-cols-2">
          <form className="p-6 md:p-8" onSubmit={handleSubmit(onSubmit)}>
            <div className="flex flex-col gap-6">
              {/*header - logo */}
              <div className="flex flex-col gap-2 text-center items-center">
                <a href="/" className="mx-auto block w-fit text-cent">
                  <img
                    src="/kudakurage-svgrepo-com.svg"
                    alt="Logo"
                    className="h-12 w-12"
                  />
                </a>
                <h1 className="text-2xl font-bold">Đăng nhập</h1>
                <p className="text-muted-foreground text-balanced">
                  Chào mừng bạn trở lại! Vui lòng đăng nhập để tiếp tục.
                </p>
              </div>
              {/* email */}
              <div className="flex flex-col gap-3">
                <Label htmlFor="username" className="block text-sm">Username</Label>
                <Input id="username" type="text" placeholder="Username" {...register("username")} />
                {errors.username && <p className="text-destructive text-sm">{errors.username.message}</p>}
              </div>
              {/* password */}
              <div className="flex flex-col gap-3">
                <Label htmlFor="password" className="block text-sm">Mật khẩu</Label>
                <Input id="password" type="password" placeholder="Mật khẩu" {...register("password")} />
                {errors.password && <p className="text-destructive text-sm">{errors.password.message}</p>}
              </div>
              {/* nút đăng ký */}
              <div>
                <Button className="w-full" disabled={isSubmitting}>Đăng nhập</Button>
              </div>
            </div>
            <div className="px-6 py-6 text-center *:[a]:hover:text-primary text-muted-foreground *:[a]:underline *:[a]:underline-offset-4 text-sm text-balanced">
              Bạn chưa có tài khoản? <a href="/register">Đăng ký</a>.
            </div>

          </form>
          <div className="bg-muted relative hidden md:block">
            <img
              src="/placeholderSignUp.png"
              alt="Image"
              className="absolute top-1/2 -translate-y-1/2 object-cover"
            />
          </div>
        </CardContent>
      </Card>
      <div className="px-6 text-center *:[a]:hover:text-primary text-muted-foreground *:[a]:underline *:[a]:underline-offset-4 text-sm text-balanced">
        Bằng cách tiếp tục, bạn đồng ý với <a href="#">Chính sách bảo mật</a>.
      </div>
    </div>
  )
}
