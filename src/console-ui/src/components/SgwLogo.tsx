import sgwIcon from "@/assets/s-gw-64.png";
import { cn } from "@/lib/utils";

export function SgwLogo({ className, showText = true }: { className?: string; showText?: boolean }) {
  return (
    <div className={cn("flex items-center gap-3", className)}>
      <img src={sgwIcon} alt="s-gw" className="h-9 w-9 rounded-md object-contain" />
      {showText ? <span className="text-lg font-semibold tracking-normal">s-gw</span> : null}
    </div>
  );
}
