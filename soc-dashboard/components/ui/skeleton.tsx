'use client';

import React from "react"

import { cn } from '@/lib/utils'
import { motion } from 'framer-motion'

function Skeleton({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <motion.div
      className={cn('rounded-md bg-gradient-to-r from-muted via-muted/50 to-muted', className)}
      animate={{ opacity: [0.4, 0.6, 0.4] }}
      transition={{ duration: 2.5, repeat: Infinity }}
      {...props}
    />
  )
}

function SkeletonCard() {
  return (
    <motion.div
      className="rounded-lg bg-card/50 border border-border/30 p-6 space-y-4"
      animate={{ opacity: [0.6, 0.8, 0.6] }}
      transition={{ duration: 2.5, repeat: Infinity }}
    >
      <div className="h-4 bg-gradient-to-r from-muted to-muted/50 rounded w-3/4" />
      <div className="h-10 bg-gradient-to-r from-muted to-muted/50 rounded w-1/2" />
      <div className="space-y-2">
        <div className="h-3 bg-gradient-to-r from-muted to-muted/50 rounded w-full" />
        <div className="h-3 bg-gradient-to-r from-muted to-muted/50 rounded w-5/6" />
      </div>
    </motion.div>
  )
}

function SkeletonTable({ rows = 5 }) {
  return (
    <div className="space-y-2">
      {[...Array(rows)].map((_, i) => (
        <motion.div
          key={i}
          className="h-12 bg-gradient-to-r from-muted to-muted/50 rounded-lg"
          animate={{ opacity: [0.6, 0.8, 0.6] }}
          transition={{ duration: 2.5, repeat: Infinity, delay: i * 0.1 }}
        />
      ))}
    </div>
  )
}

export { Skeleton, SkeletonCard, SkeletonTable }
