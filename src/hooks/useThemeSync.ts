import { useEffect } from "react";
import { useUi } from "../stores/ui";

/** Applies theme, text size and motion preferences to <html>. */
export function useThemeSync() {
  const theme = useUi((s) => s.theme);
  const textScale = useUi((s) => s.textScale);
  const motion = useUi((s) => s.motion);
  useEffect(() => {
    document.documentElement.style.setProperty("--text-scale", String(textScale));
    if (motion === "reduce") document.documentElement.dataset.motion = "reduce";
    else delete document.documentElement.dataset.motion;
  }, [textScale, motion]);
  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: light)");
    const apply = () => {
      const resolved = theme === "system" ? (media.matches ? "light" : "dark") : theme;
      document.documentElement.dataset.theme = resolved;
    };
    apply();
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [theme]);
}
