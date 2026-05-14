"use client";

// Thin wrapper over sonner. Keeps a stable `useToast()` hook surface so the
// rest of the app doesn't import sonner directly; lets us swap the lib later
// without touching call sites.

import { Toaster, toast as sonnerToast } from "sonner";
import type { ReactNode } from "react";

interface ToastApi {
  success: (message: string, detail?: string) => void;
  error: (message: string, detail?: string) => void;
  info: (message: string, detail?: string) => void;
}

export function ToastProvider({ children }: { children: ReactNode }) {
  return (
    <>
      {children}
      <Toaster
        position="bottom-right"
        theme="dark"
        closeButton
        toastOptions={{
          duration: 4_000,
          // Errors are sticky — operators want to read them.
          classNames: {
            error: "sb-toast-error",
            success: "sb-toast-success",
            info: "sb-toast-info",
          },
        }}
      />
    </>
  );
}

const api: ToastApi = {
  success: (message, detail) =>
    void sonnerToast.success(message, detail !== undefined ? { description: detail } : undefined),
  info: (message, detail) =>
    void sonnerToast(message, detail !== undefined ? { description: detail } : undefined),
  error: (message, detail) =>
    void sonnerToast.error(message, {
      duration: Infinity,
      ...(detail !== undefined ? { description: detail } : {}),
    }),
};

export function useToast(): ToastApi {
  return api;
}
