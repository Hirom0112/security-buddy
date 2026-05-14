"use client";

import { forwardRef, type ButtonHTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/cn";

// Minimal Button primitive. Variants map to our project's neon/danger/muted
// vocabulary. Used for primary actions in the dashboard. Status pills and
// the halt button still own their bespoke styles in dashboard.module.css —
// those are designed as state expressions, not affordances.

const buttonVariants = cva(
  // base
  [
    "inline-flex items-center justify-center gap-2 whitespace-nowrap",
    "rounded-md font-medium",
    "transition-[border-color,background-color,color] duration-150 ease-out",
    "focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2",
    "disabled:pointer-events-none disabled:opacity-60",
  ],
  {
    variants: {
      variant: {
        primary:
          "bg-[var(--sb-neon)] text-[#04111d] hover:brightness-110 focus-visible:outline-[var(--sb-neon)]",
        outline:
          "border border-[var(--sb-border-bright)] bg-transparent text-[var(--sb-fg)] hover:border-[var(--sb-neon)]/60 hover:bg-[var(--sb-neon)]/[0.06] focus-visible:outline-[var(--sb-neon)]",
        danger:
          "border border-[var(--sb-danger)]/45 bg-transparent text-[var(--sb-danger)] hover:bg-[var(--sb-danger)]/[0.08] hover:border-[var(--sb-danger)] focus-visible:outline-[var(--sb-danger)]",
        ghost:
          "bg-transparent text-[var(--sb-muted)] hover:bg-white/5 hover:text-[var(--sb-fg)] focus-visible:outline-[var(--sb-border-bright)]",
      },
      size: {
        sm: "h-7 px-2.5 text-xs",
        md: "h-9 px-3.5 text-sm",
        lg: "h-10 px-4 text-sm",
      },
    },
    defaultVariants: {
      variant: "outline",
      size: "md",
    },
  }
);

export interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => (
    <button
      ref={ref}
      type={props.type ?? "button"}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  )
);
Button.displayName = "Button";

export { buttonVariants };
