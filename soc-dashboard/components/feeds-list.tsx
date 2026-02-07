'use client'

import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { SkeletonTable } from '@/components/ui/skeleton'
import { CheckCircle, AlertCircle } from 'lucide-react'

export default function FeedsList() {
  const [feeds, setFeeds] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchFeeds = async () => {
      try {
        const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/feeds`)
        const data = await response.json()
        setFeeds(data.feeds || [])
      } catch (error) {
        console.error('Failed to fetch feeds:', error)
      } finally {
        setLoading(false)
      }
    }
    fetchFeeds()
  }, [])

  if (loading) {
    return (
      <Card className="overflow-hidden border-border/30 bg-card/50 backdrop-blur-sm p-6">
        <SkeletonTable rows={6} />
      </Card>
    )
  }

  const getPriorityColor = (priority: string) => {
    switch (priority?.toLowerCase()) {
      case 'critical':
        return 'bg-red-500/20 text-red-400 border-red-500/30'
      case 'high':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
      default:
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30'
    }
  }

  const rowVariants = {
    hidden: { opacity: 0, x: -20 },
    visible: (idx: number) => ({
      opacity: 1,
      x: 0,
      transition: {
        delay: idx * 0.05,
        duration: 0.4,
        ease: 'easeOut',
      },
    }),
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      <Card className="overflow-hidden border-border/30 bg-card/50 backdrop-blur-sm">
        <Table>
          <TableHeader>
            <TableRow className="border-border/50 hover:bg-secondary/50">
              <TableHead>Feed Name</TableHead>
              <TableHead>Category</TableHead>
              <TableHead>Priority</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Success / Failed</TableHead>
              <TableHead className="text-right">Response Time</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {feeds.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                  No feeds available
                </TableCell>
              </TableRow>
            ) : (
              feeds.map((feed, idx) => (
                <motion.tr
                  key={idx}
                  custom={idx}
                  variants={rowVariants}
                  initial="hidden"
                  animate="visible"
                  whileHover={{ scale: 1.01, backgroundColor: 'rgba(6, 182, 212, 0.05)' }}
                  className="border-border/30 transition-colors"
                >
                  <TableCell className="font-medium text-foreground">{feed.name}</TableCell>
                  <TableCell className="text-muted-foreground capitalize">{feed.category}</TableCell>
                  <TableCell>
                    <Badge className={getPriorityColor(feed.priority)}>{feed.priority}</Badge>
                  </TableCell>
                  <TableCell>
                    {feed.failure_count === 0 ? (
                      <motion.div
                        className="flex items-center gap-2 text-green-400"
                        animate={{ opacity: [0.7, 1, 0.7] }}
                        transition={{ duration: 2, repeat: Infinity }}
                      >
                        <CheckCircle className="h-4 w-4" />
                        Healthy
                      </motion.div>
                    ) : (
                      <motion.div
                        className="flex items-center gap-2 text-red-400"
                        animate={{ opacity: [0.7, 1, 0.7] }}
                        transition={{ duration: 2, repeat: Infinity }}
                      >
                        <AlertCircle className="h-4 w-4" />
                        Issues
                      </motion.div>
                    )}
                  </TableCell>
                  <TableCell className="text-right text-muted-foreground">
                    {feed.success_count} / {feed.failure_count}
                  </TableCell>
                  <TableCell className="text-right text-muted-foreground text-sm">
                    {feed.last_response_time?.toFixed(2)}ms
                  </TableCell>
                </motion.tr>
              ))
            )}
          </TableBody>
        </Table>
      </Card>
    </motion.div>
  )
}
