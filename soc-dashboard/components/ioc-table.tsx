'use client'

import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { SkeletonTable } from '@/components/ui/skeleton'
import { EmptyState } from '@/components/empty-state'

export default function IOCTable() {
  const [iocs, setIOCs] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [iocType, setIOCType] = useState<string>('all')
  const [severity, setSeverity] = useState<string>('all')
  const [limit, setLimit] = useState(50)

  useEffect(() => {
    const fetchIOCs = async () => {
      setLoading(true)
      try {
        let url = `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/iocs?limit=` + limit
        if (iocType !== 'all') url += '&ioc_type=' + iocType
        if (severity !== 'all') url += '&severity=' + severity

        const response = await fetch(url)
        const data = await response.json()
        setIOCs(data.iocs || [])
      } catch (error) {
        console.error('Failed to fetch IOCs:', error)
      } finally {
        setLoading(false)
      }
    }
    fetchIOCs()
  }, [iocType, severity, limit])

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'bg-red-500/20 text-red-400 border-red-500/30'
      case 'high':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
      default:
        return 'bg-green-500/20 text-green-400 border-green-500/30'
    }
  }

  const getTypeColor = (type: string) => {
    const colors: Record<string, string> = {
      ip: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
      domain: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
      url: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
      hash: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30',
    }
    return colors[type] || 'bg-gray-500/20 text-gray-400 border-gray-500/30'
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Select value={iocType} onValueChange={setIOCType}>
          <SelectTrigger>
            <SelectValue placeholder="All IOC Types" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Types</SelectItem>
            <SelectItem value="ip">IP Address</SelectItem>
            <SelectItem value="domain">Domain</SelectItem>
            <SelectItem value="url">URL</SelectItem>
            <SelectItem value="hash">Hash</SelectItem>
          </SelectContent>
        </Select>

        <Select value={severity} onValueChange={setSeverity}>
          <SelectTrigger>
            <SelectValue placeholder="All Severities" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="Critical">Critical</SelectItem>
            <SelectItem value="High">High</SelectItem>
            <SelectItem value="Medium">Medium</SelectItem>
            <SelectItem value="Low">Low</SelectItem>
          </SelectContent>
        </Select>

        <Select value={limit.toString()} onValueChange={(v) => setLimit(parseInt(v))}>
          <SelectTrigger>
            <SelectValue placeholder="Limit" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="10">10 Results</SelectItem>
            <SelectItem value="25">25 Results</SelectItem>
            <SelectItem value="50">50 Results</SelectItem>
            <SelectItem value="100">100 Results</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <Card className="overflow-hidden border-border/30 bg-card/50 backdrop-blur-sm">
          <Table>
            <TableHeader>
              <TableRow className="border-border/50 hover:bg-secondary/50">
                <TableHead>IOC Value</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Feed Source</TableHead>
                <TableHead>Timestamp</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={5} className="py-4">
                    <SkeletonTable rows={5} />
                  </TableCell>
                </TableRow>
              ) : iocs.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="py-0">
                    <EmptyState
                      type="no-results"
                      title="No IOCs Found"
                      description="No indicators of compromise match your current filters. Try adjusting the severity level or IOC type."
                    />
                  </TableCell>
                </TableRow>
              ) : (
                iocs.map((ioc, idx) => (
                  <motion.tr
                    key={idx}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.03, duration: 0.4 }}
                    whileHover={{ scale: 1.01, backgroundColor: 'rgba(6, 182, 212, 0.05)' }}
                    className="border-border/30 transition-colors"
                  >
                    <TableCell className="font-mono text-sm text-foreground break-all">{ioc.ioc}</TableCell>
                    <TableCell>
                      <Badge className={getTypeColor(ioc.type)}>{ioc.type.toUpperCase()}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge className={getSeverityColor(ioc.severity)}>{ioc.severity}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">{ioc.feed}</TableCell>
                    <TableCell className="text-muted-foreground text-sm whitespace-nowrap">
                      {new Date(ioc.timestamp).toLocaleString()}
                    </TableCell>
                  </motion.tr>
                ))
              )}
            </TableBody>
          </Table>
        </Card>
      </motion.div>
    </div>
  )
}
