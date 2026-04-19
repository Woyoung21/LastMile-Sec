import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";

import { AppShell } from "@/components/AppShell";
import { JobProvider } from "@/context/JobContext";
import { RemediationProvider } from "@/context/RemediationContext";

import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "LastMile Sec",
  description: "Operator dashboard — ingestion, MITRE mapping, remediation",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} min-h-screen antialiased`}
      >
        <div className="flex min-h-screen flex-col">
          <JobProvider>
            <RemediationProvider>
              <AppShell>{children}</AppShell>
            </RemediationProvider>
          </JobProvider>
        </div>
      </body>
    </html>
  );
}
