import type { ButtonHTMLAttributes } from "react";

const variants = {
  primary: "bg-accent text-accent-ink hover:brightness-110",
  secondary: "bg-raised text-text border border-line hover:bg-hover",
  ghost: "text-muted hover:bg-hover hover:text-text",
  danger: "bg-bad text-white hover:brightness-110",
};

export type ButtonVariant = keyof typeof variants;

export function Button({
  variant = "secondary",
  className = "",
  type = "button",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  return (
    <button
      type={type}
      className={`inline-flex h-8 shrink-0 items-center justify-center gap-2 rounded-control px-3 font-medium transition-[background-color,filter] disabled:pointer-events-none disabled:opacity-45 ${variants[variant]} ${className}`}
      {...props}
    />
  );
}
