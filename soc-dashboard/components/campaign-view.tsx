'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import {
  Target,
  Clock,
  TrendingUp,
  ChevronDown,
  ChevronUp,
  Crosshair,
  Flame,
  Zap,
  Eye,
} from 'lucide-react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

const SEVERITY_BADGE: Record<string, { color: string; bg: string }> = {
  Critical: { color: 'text-red-400', bg: 'bg-red-500/15 border-red-500/30' },
  High: { color: 'text-orange-400', bg: 'bg-orange-500/15 border-orange-500/30' },
  Medium: { color: 'text-yellow-400', bg: 'bg-yellow-500/15 border-yellow-500/30' },
  Low: { color: 'text-green-400', bg: 'bg-green-500/15 border-green-500/30' },
  Unknown: { color: 'text-gray-400', bg: 'bg-gray-500/15 border-gray-500/30' },
}

function getTopSeverity(dist: Record<string, number> | undefined): string {
  if (!dist) return 'Unknown'
  for (const sev of ['Critical', 'High', 'Medium', 'Low']) {
    if ((dist[sev] || 0) > 0) return sev
  }
  return 'Unknown'
}

function formatDuration(hours: number): string {
  if (hours < 1) return `${Math.round(hours * 60)}m`
  if (hours < 24) return `${Math.round(hours)}h`
  return `${Math.round(hours / 24)}d`
}

export default function CampaignView() {
  const [campaigns, setCampaigns] = useState<any[]>([])
  const [stats, setStats] = useState<any>(null)
  const [timeline, setTimeline] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [campaignDetail, setCampaignDetail] = useState<any>(null)
  const [detailLoading, setDetailLoading] = useState(false)

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const [campRes, statsRes, timelineRes] = await Promise.all([
          fetch(`${API_URL}/api/campaigns?limit=50&sort_by=last_seen`),
          fetch(`${API_URL}/api/campaigns/stats`),
          fetch(`${API_URL}/api/campaigns/timeline?period=30d`),
        ])
        const campData = await campRes.json()
        setCampaigns(campData.campaigns || [])
        setStats(await statsRes.json())
        const tlData = await timelineRes.json()
        setTimeline(tlData.data || [])
      } catch (err) {
        console.error('Failed to fetch campaign data:', err)
      } finally {
        setLoading(false)
      }
    }
    fetchAll()
  }, [])

  const handleExpand = async (campaignId: string) => {
    if (expandedId === campaignId) {
      setExpandedId(null)
      setCampaignDetail(null)
      return
    }
    setExpandedId(campaignId)
    setDetailLoading(true)
    try {
      const res = await fetch(`${API_URL}/api/campaigns/${campaignId}`)
      setCampaignDetail(await res.json())
    } catch (err) {
      console.error('Failed to fetch campaign detail:', err)
    } finally {
      setDetailLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <Card key={i} className="p-6 h-28 animate-pulse bg-gradient-to-r from-muted to-muted/50" />
          ))}
        </div>
        <Card className="p-6 h-64 animate-pulse bg-gradient-to-r from-muted to-muted/50" />
      </div>
    )
  }

  const container = {
    hidden: { opacity: 0 },
    visible: { opacity: 1, transition: { staggerChildren: 0.1, delayChildren: 0 } },
  }
  const item = {
    hidden: { opacity: 0, y: 16 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.4 } },
  }

  return (
    <motion.div className="space-y-6" variants={container} initial="hidden" animate="visible">

      {/* Stats Cards */}
      <motion.div className="grid grid-cols-2 md:grid-cols-4 gap-4" variants={item}>
        <Card className="bg-card/80 backdrop-blur-sm border-border/30 hover:border-primary/40 transition-colors">
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-primary/10">
                <Target className="h-5 w-5 text-primary" />
              </div>
              <div>
                <p className="text-2xl font-bold text-foreground">{stats?.total_campaigns ?? 0}</p>
                <p className="text-xs text-muted-foreground">Total Campaigns</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/80 backdrop-blur-sm border-border/30 hover:border-red-500/40 transition-colors">
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-red-500/10">
                <Flame className="h-5 w-5 text-red-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-foreground">{stats?.active_campaigns ?? 0}</p>
                <p className="text-xs text-muted-foreground">Active (48h)</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/80 backdrop-blur-sm border-border/30 hover:border-yellow-500/40 transition-colors">
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-yellow-500/10">
                <Zap className="h-5 w-5 text-yellow-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-foreground">{stats?.avg_ioc_count ?? 0}</p>
                <p className="text-xs text-muted-foreground">Avg IOCs/Campaign</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/80 backdrop-blur-sm border-border/30 hover:border-cyan-500/40 transition-colors">
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyan-500/10">
                <Crosshair className="h-5 w-5 text-cyan-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-foreground">{stats?.total_iocs_in_campaigns ?? 0}</p>
                <p className="text-xs text-muted-foreground">IOCs In Campaigns</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Timeline Chart */}
      <motion.div variants={item}>
        <Card className="bg-card/80 backdrop-blur-sm border-border/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-primary" />
              Campaign Activity (30 Days)
            </CardTitle>
            <CardDescription>Active and newly detected campaigns over time</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={timeline} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="activeGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#06b6d4" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#06b6d4" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="newGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#f59e0b" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#f59e0b" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(200, 10%, 20%)" />
                <XAxis dataKey="period" tick={{ fill: '#9ca3af', fontSize: 11 }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'hsl(200, 15%, 10%)',
                    border: '1px solid hsl(200, 10%, 25%)',
                    borderRadius: '8px',
                    color: '#f3f4f6',
                    fontSize: 12,
                  }}
                />
                <Area type="monotone" dataKey="active_campaigns" name="Active" stroke="#06b6d4" fill="url(#activeGrad)" strokeWidth={2} />
                <Area type="monotone" dataKey="new_campaigns" name="New" stroke="#f59e0b" fill="url(#newGrad)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </motion.div>

      {/* Campaign List */}
      <motion.div variants={item}>
        <Card className="bg-card/80 backdrop-blur-sm border-border/30">
          <CardHeader className="pb-3">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <Eye className="h-4 w-4 text-primary" />
              Detected Campaigns
              <Badge variant="outline" className="ml-2 text-xs font-mono">{campaigns.length}</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {campaigns.length === 0 ? (
              <div className="text-center py-12 text-muted-foreground">
                <Target className="h-12 w-12 mx-auto mb-3 opacity-30" />
                <p className="text-sm">No campaigns detected yet</p>
                <p className="text-xs mt-1 opacity-60">
                  Campaigns will appear after the Knowledge Graph has enough IOC data for Louvain clustering
                </p>
              </div>
            ) : (
              campaigns.map((c: any) => {
                const topSev = getTopSeverity(c.severity_distribution)
                const sevStyle = SEVERITY_BADGE[topSev] || SEVERITY_BADGE.Unknown
                const isExpanded = expandedId === c.campaign_id

                return (
                  <motion.div
                    key={c.campaign_id}
                    layout
                    className="rounded-lg border border-border/40 bg-secondary/30 hover:bg-secondary/50 transition-colors overflow-hidden"
                  >
                    {/* Campaign Row */}
                    <button
                      onClick={() => handleExpand(c.campaign_id)}
                      className="w-full px-4 py-3 flex items-center justify-between text-left"
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <Badge className={`${sevStyle.bg} ${sevStyle.color} border text-[10px] font-semibold px-2 py-0.5`}>
                          {topSev}
                        </Badge>
                        <span className="text-sm font-medium text-foreground truncate">{c.label}</span>
                      </div>
                      <div className="flex items-center gap-4 shrink-0">
                        <span className="text-xs text-muted-foreground font-mono">{c.ioc_count} IOCs</span>
                        <span className="text-xs text-muted-foreground flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {formatDuration(c.duration_hours)}
                        </span>
                        <span className="text-xs text-muted-foreground">
                          conf: {(c.avg_confidence * 100).toFixed(0)}%
                        </span>
                        {isExpanded ? (
                          <ChevronUp className="h-4 w-4 text-muted-foreground" />
                        ) : (
                          <ChevronDown className="h-4 w-4 text-muted-foreground" />
                        )}
                      </div>
                    </button>

                    {/* Expanded Detail */}
                    {isExpanded && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="px-4 pb-4 border-t border-border/30"
                      >
                        {detailLoading ? (
                          <div className="py-6 text-center text-xs text-muted-foreground animate-pulse">Loading...</div>
                        ) : campaignDetail ? (
                          <div className="pt-3 space-y-3">
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                              <div>
                                <span className="text-muted-foreground">First Seen</span>
                                <p className="text-foreground font-mono mt-0.5">{new Date(campaignDetail.first_seen).toLocaleString()}</p>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Last Seen</span>
                                <p className="text-foreground font-mono mt-0.5">{new Date(campaignDetail.last_seen).toLocaleString()}</p>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Max Confidence</span>
                                <p className="text-foreground font-mono mt-0.5">{(campaignDetail.max_confidence * 100).toFixed(1)}%</p>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Severity Breakdown</span>
                                <div className="flex gap-1 mt-1 flex-wrap">
                                  {Object.entries(campaignDetail.severity_distribution || {}).map(([sev, count]) => {
                                    const s = SEVERITY_BADGE[sev] || SEVERITY_BADGE.Unknown
                                    return (
                                      <Badge key={sev} className={`${s.bg} ${s.color} border text-[10px] px-1.5 py-0`}>
                                        {sev}: {count as number}
                                      </Badge>
                                    )
                                  })}
                                </div>
                              </div>
                            </div>
                            <Separator className="bg-border/30" />
                            <div>
                              <span className="text-xs text-muted-foreground">IOC Members ({campaignDetail.ioc_count})</span>
                              <div className="mt-1.5 flex flex-wrap gap-1.5 max-h-36 overflow-y-auto">
                                {(campaignDetail.ioc_members || []).map((ioc: string) => (
                                  <Badge
                                    key={ioc}
                                    variant="outline"
                                    className="font-mono text-[10px] text-foreground/80 bg-muted/30 border-border/50"
                                  >
                                    {ioc}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          </div>
                        ) : null}
                      </motion.div>
                    )}
                  </motion.div>
                )
              })
            )}
          </CardContent>
        </Card>
      </motion.div>
    </motion.div>
  )
}
