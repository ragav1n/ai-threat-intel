'use client'

import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Card } from '@/components/ui/card'
import { SkeletonCard } from '@/components/ui/skeleton'
import { AlertTriangle, Database, CheckCircle, TrendingUp } from 'lucide-react'

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1,
      delayChildren: 0.2,
    },
  },
}

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.5, ease: 'easeOut' },
  },
}

export default function DashboardStats() {
  const [feedStats, setFeedStats] = useState<any>(null)
  const [iocStats, setIocStats] = useState<any>(null)
  const [summaryStats, setSummaryStats] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  // Fetch stats with polling for real-time updates
  useEffect(() => {
    const fetchStats = async () => {
      try {
        const [feedRes, iocRes, summaryRes] = await Promise.all([
          fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/feeds/stats`),
          fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/iocs/stats`),
          fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/summaries/stats`),
        ])
        setFeedStats(await feedRes.json())
        setIocStats(await iocRes.json())
        setSummaryStats(await summaryRes.json())
      } catch (error) {
        console.error('Failed to fetch stats:', error)
      } finally {
        setLoading(false)
      }
    }
    fetchStats()

    // Poll every 15 seconds for real-time updates
    const interval = setInterval(fetchStats, 15000)
    return () => clearInterval(interval)
  }, [])

  if (loading) {
    return (
      <motion.div
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4"
        variants={containerVariants}
        initial="hidden"
        animate="visible"
      >
        {[...Array(4)].map((_, i) => (
          <motion.div key={i} variants={itemVariants}>
            <SkeletonCard />
          </motion.div>
        ))}
      </motion.div>
    )
  }

  const stats = [
    {
      label: 'Active Feeds',
      value: feedStats?.success || 0,
      total: feedStats?.total || 0,
      icon: Database,
      color: 'text-primary',
    },
    {
      label: 'IOC Indicators',
      value: iocStats?.total || 0,
      icon: TrendingUp,
      color: 'text-yellow-500',
    },
    {
      label: 'High Severity',
      value: iocStats?.by_severity?.High || 0,
      icon: AlertTriangle,
      color: 'text-red-500',
    },
    {
      label: 'Feed Success Rate',
      value: feedStats?.success_rate || '0%',
      icon: CheckCircle,
      color: 'text-green-500',
    },
  ]

  return (
    <motion.div
      className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {stats.map((stat, idx) => {
        const Icon = stat.icon
        return (
          <motion.div key={idx} variants={itemVariants}>
            <motion.div
              whileHover={{ scale: 1.05, translateY: -5 }}
              whileTap={{ scale: 0.95 }}
              transition={{ type: 'spring', stiffness: 400, damping: 25 }}
            >
              <Card className="p-6 border-border/50 hover:border-primary/50 transition-colors cursor-pointer h-full bg-card/50 backdrop-blur-sm border-border/30">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground mb-1">{stat.label}</p>
                    <motion.p
                      className="text-2xl font-bold text-foreground"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: 0.3 + idx * 0.1 }}
                    >
                      {stat.value}
                    </motion.p>
                    {stat.total && <p className="text-xs text-muted-foreground mt-1">of {stat.total}</p>}
                  </div>
                  <motion.div
                    animate={{ y: [0, -8, 0] }}
                    transition={{ duration: 3, repeat: Infinity, delay: idx * 0.2 }}
                  >
                    <Icon className={`h-8 w-8 ${stat.color} opacity-80`} />
                  </motion.div>
                </div>
              </Card>
            </motion.div>
          </motion.div>
        )
      })}
    </motion.div>
  )
}
