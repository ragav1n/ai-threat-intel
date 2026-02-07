import React from "react"
import type { Metadata } from 'next'
import { Space_Grotesk, Space_Mono } from 'next/font/google'
import { Toaster } from '@/components/ui/toaster'

import './globals.css'

const spaceGrotesk = Space_Grotesk({ subsets: ['latin'], variable: '--font-space-grotesk' })
const spaceMono = Space_Mono({ subsets: ['latin'], weight: ['400', '700'], variable: '--font-space-mono' })

export const metadata: Metadata = {
  title: 'Threat Intelligence Dashboard',
  description: 'SOC threat intelligence and security monitoring dashboard',
  generator: 'v0.app',
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" className={`${spaceGrotesk.variable} ${spaceMono.variable}`}>
      <body className="font-sans antialiased">
        {children}
        <Toaster />
      </body>
    </html>
  )
}
