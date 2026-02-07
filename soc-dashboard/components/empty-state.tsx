'use client'

import React from "react"

import { motion } from 'framer-motion'
import { AlertCircle, Database, Search } from 'lucide-react'
import { Button } from '@/components/ui/button'

interface EmptyStateProps {
  type: 'no-data' | 'no-results' | 'error'
  title: string
  description: string
  icon?: React.ReactNode
  action?: { label: string; onClick: () => void }
}

export function EmptyState({
  type,
  title,
  description,
  icon,
  action,
}: EmptyStateProps) {
  const defaultIcons = {
    'no-data': <Database className="h-12 w-12 text-muted-foreground" />,
    'no-results': <Search className="h-12 w-12 text-muted-foreground" />,
    'error': <AlertCircle className="h-12 w-12 text-destructive" />,
  }

  return (
    <motion.div
      className="flex flex-col items-center justify-center py-16 px-4"
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.4, ease: 'easeOut' }}
    >
      <motion.div
        className="mb-4"
        animate={{ y: [0, -8, 0] }}
        transition={{ duration: 3, repeat: Infinity }}
      >
        {icon || defaultIcons[type]}
      </motion.div>

      <h3 className="text-lg font-semibold text-foreground mb-2 text-center">{title}</h3>
      <p className="text-sm text-muted-foreground text-center max-w-sm mb-6">{description}</p>

      {action && (
        <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
          <Button onClick={action.onClick} variant="outline" size="sm">
            {action.label}
          </Button>
        </motion.div>
      )}
    </motion.div>
  )
}
