import { cn } from "@/lib/utils"
  
export function SpinnerCustom({ className }: { className?: string }) {
    return (
        <div className={cn("flex items-center justify-center h-full", className)}>
            <img
                src="/uia.gif"
                alt="Loading..."
                className="w-40 h-40"
            />
        </div>
    )
}