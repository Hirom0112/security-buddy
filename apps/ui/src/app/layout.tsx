import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Security Buddy",
  description: "Adversarial evaluation platform for AI-assisted clinical workflows",
  robots: {
    index: false,
    follow: false,
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-background font-sans antialiased">
        {children}
      </body>
    </html>
  );
}
