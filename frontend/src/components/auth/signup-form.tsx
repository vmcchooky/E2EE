import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Label } from "@radix-ui/react-label"
import { Input } from "../ui/input"
import { set, z } from "zod"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { useAuthStore } from "@/stores/useAuthStore"
import { useE2EEStore } from "@/stores/useE2EEStore"
import { useNavigate } from "react-router"

const signUpSchema = z.object({
  firstname: z.string().min(1, "Tên bắt buộc phải có"),
  lastname: z.string().min(1, "Họ bắt buộc phải có"),
  username: z.string().min(3, "Tên đăng nhập phải có ít nhất 3 ký tự"),
  email: z.email("Địa chỉ email không hợp lệ"),
  password: z.string().min(6, "Mật khẩu phải có ít nhất 6 ký tự"),
})

type SignUpFormValues = z.infer<typeof signUpSchema>

export function SignupForm({
  className,
  ...props
}: React.ComponentProps<"div">) {
  const { signUp } = useAuthStore();
  const { generateKeyForUser } = useE2EEStore();
  const navigate = useNavigate();

  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<SignUpFormValues>({
    resolver: zodResolver(signUpSchema),
  });

  const onSubmit = async (data: SignUpFormValues) => {
    const { firstname, lastname, username, email, password } = data;
    try {
      // Step 1: Register user
      await signUp(username, password, email, firstname, lastname);

      // Step 2: After successful registration, we need to login to get user ID
      // Then generate E2EE key for the new user
      // Note: We'll generate key after first login since we need user._id
      // For now, navigate to login - key will be generated on first login if missing

      navigate("/login");
    } catch (error) {
      console.error(error);
    }
  }


  return (
    <div className={cn("flex flex-col gap-6", className)} {...props}>
      <Card className="overflow-hidden p-0 border-border">
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
                <h1 className="text-2xl font-bold">Tạo tài khoản</h1>
                <p className="text-muted-foreground text-balanced">
                  Chào mừng bạn đến với ChatApp! Hãy đăng ký để bắt đầu
                </p>
              </div>

              {/* Họ và tên */}
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label htmlFor="lastname" className="block text-sm">Họ</Label>
                  <Input id="lastname" type="text" placeholder="Họ"
                    {...register("lastname")} />
                  {errors.lastname && <p className="text-destructive text-sm">{errors.lastname.message}</p>}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="firstname" className="block text-sm">Tên</Label>
                  <Input id="firstname" type="text" placeholder="Tên" {...register("firstname")} />
                  {errors.firstname && <p className="text-destructive text-sm">{errors.firstname.message}</p>}
                </div>
              </div>

              {/* user name */}
              <div className="flex flex-col gap-3">
                <Label htmlFor="username" className="block text-sm">Tên đăng nhập</Label>
                <Input id="username" type="text" placeholder="Tên đăng nhập" {...register("username")} />
                {errors.username && <p className="text-destructive text-sm">{errors.username.message}</p>}
              </div>

              {/* email */}
              <div className="flex flex-col gap-3">
                <Label htmlFor="email" className="block text-sm">Email</Label>
                <Input id="email" type="email" placeholder="Email" {...register("email")} />
                {errors.email && <p className="text-destructive text-sm">{errors.email.message}</p>}
              </div>
              {/* password */}
              <div className="flex flex-col gap-3">
                <Label htmlFor="password" className="block text-sm">Mật khẩu</Label>
                <Input id="password" type="password" placeholder="Mật khẩu" {...register("password")} />
                {errors.password && <p className="text-destructive text-sm">{errors.password.message}</p>}
              </div>

              <Button type="submit" className="w-full" disabled={isSubmitting}>
                Đăng ký
              </Button>
              {/* nút đăng ký */}

              <div className="px-6 text-center *:[a]:hover:text-primary text-muted-foreground *:[a]:underline *:[a]:underline-offset-4 text-sm text-balanced">Bạn đã có tài khoản? <a href="/login" className="underline underline-offset-4">Đăng nhập</a></div>

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
