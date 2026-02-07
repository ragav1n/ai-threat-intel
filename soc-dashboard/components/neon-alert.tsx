'use client'

import { motion } from 'framer-motion'
import { AlertTriangle } from 'lucide-react'
import { Badge } from '@/components/ui/badge'

interface NeonAlertProps {
  severity: 'critical' | 'high' | 'medium' | 'low'
  title: string
  count?: number
}

const severityConfig = {
  critical: {
    color: 'text-red-500',
    glow: 'shadow-lg shadow-red-500/50',
    bg: 'bg-red-500/10 border-red-500/30',
    label: 'Critical',
  },
  high: {
    color: 'text-orange-500',
    glow: 'shadow-lg shadow-orange-500/50',
    bg: 'bg-orange-500/10 border-orange-500/30',
    label: 'High',
  },
  medium: {
    color: 'text-yellow-500',
    glow: 'shadow-lg shadow-yellow-500/30',
    bg: 'bg-yellow-500/10 border-yellow-500/30',
    label: 'Medium',
  },
  low: {
    color: 'text-green-500',
    glow: 'shadow-lg shadow-green-500/30',
    bg: 'bg-green-500/10 border-green-500/30',
    label: 'Low',
  },
}

export function NeonAlert({ severity, title, count }: NeonAlertProps) {
  const config = severityConfig[severity]

  return (
    <motion.div
      className={`rounded-lg border p-4 ${config.bg} ${config.glow}`}
      animate={{
        boxShadow: [
          `0 0 20px ${severity === 'critical' ? 'rgba(239, 68, 68, 0.4)' : severity === 'high' ? 'rgba(249, 115, 22, 0.4)' : severity === 'medium' ? 'rgba(234, 179, 8, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`,
          `0 0 40px ${severity === 'critical' ? 'rgba(239, 68, 68, 0.6)' : severity === 'high' ? 'rgba(249, 115, 22, 0.6)' : severity === 'medium' ? 'rgba(234, 179, 8, 0.4)' : 'rgba(34, 197, 94, 0.4)'}`,
          `0 0 20px ${severity === 'critical' ? 'rgba(239, 68, 68, 0.4)' : severity === 'high' ? 'rgba(249, 115, 22, 0.4)' : severity === 'medium' ? 'rgba(234, 179, 8, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`,
        ],
      }}
      transition={{ duration: 2, repeat: Infinity }}
    >
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <motion.div
            animate={{ scale: [1, 1.1, 1] }}
            transition={{ duration: 2, repeat: Infinity }}
          >
            <AlertTriangle className={`h-5 w-5 ${config.color}`} />
          </motion.div>
          <div>
            <p className="text-sm font-semibold text-foreground">{title}</p>
          </div>
        </div>
        {count !== undefined && (
          <motion.div
            animate={{ scale: [1, 1.05, 1] }}
            transition={{ duration: 2, repeat: Infinity }}
          >
            <Badge className={`${config.color} bg-transparent border ${config.color}`}>
              {count}
            </Badge>
          </motion.div>
        )}
      </div>
    </motion.div>
  )
}
