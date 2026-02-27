'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { AlertCircle, Shield, Activity, Download, Mail, RefreshCw, TrendingUp, Network, Target, Brain } from 'lucide-react'
import DashboardStats from '@/components/dashboard-stats'
import FeedsList from '@/components/feeds-list'
import IOCTable from '@/components/ioc-table'
import SummariesList from '@/components/summaries-list'
import { NeonAlert } from '@/components/neon-alert'
import { useToast } from '@/hooks/use-toast'
import { EtherealShadow } from '@/components/ui/ethereal-shadow'
import SizedPieChart from '@/components/ui/sized-pie-chart'
import BarChartMedium from '@/components/ui/bar-chart-medium'
import HorizontalBarMedium from '@/components/ui/horizontal-bar-medium'
import AttackFrequencyChart from '@/components/attack-frequency-chart'
import KnowledgeGraphView from '@/components/knowledge-graph/graph-view'
import CampaignView from '@/components/campaign-view'
import PredictionView from '@/components/prediction-view'

const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#22c55e',
  Unknown: '#6b7280',
}

const IOC_TYPE_COLORS: Record<string, string> = {
  ip: '#06b6d4',
  domain: '#f59e0b',
  hash: '#ef4444',
  url: '#8b5cf6',
  sha256: '#10b981',
  sha1: '#ec4899',
  md5: '#f43f5e',
  email: '#6366f1',
}

function OverviewTab() {
  const [iocStats, setIocStats] = useState<any>(null)
  const [summaryStats, setSummaryStats] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [iocRes, summaryRes] = await Promise.all([
          fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/iocs/stats`),
          fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/summaries/stats`),
        ])
        setIocStats(await iocRes.json())
        setSummaryStats(await summaryRes.json())
      } catch (error) {
        console.error('Failed to fetch overview data:', error)
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [])

  if (loading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {[...Array(3)].map((_, i) => (
          <Card key={i} className="p-6 h-80 animate-pulse bg-gradient-to-r from-muted to-muted/50" />
        ))}
      </div>
    )
  }

  // Transform IOC type data for pie chart
  const pieChartData = iocStats?.by_type
    ? Object.entries(iocStats.by_type).map(([name, value]) => ({
      name: name.toUpperCase(),
      value: value as number,
      fill: IOC_TYPE_COLORS[name.toLowerCase()] || '#8b5cf6',
    }))
    : []

  // Transform severity data for vertical bar chart
  const severityBarData = summaryStats?.by_severity
    ? Object.entries(summaryStats.by_severity).map(([name, value]) => ({
      key: name,
      data: value as number,
    }))
    : []

  // Transform top feeds data for horizontal bar chart
  const topFeedsData = iocStats?.top_feeds
    ? Object.entries(iocStats.top_feeds).map(([name, value]) => ({
      key: name,
      data: value as number,
    }))
    : []

  return (
    <motion.div
      className="grid grid-cols-1 md:grid-cols-2 gap-6"
      variants={{
        hidden: { opacity: 0 },
        visible: {
          opacity: 1,
          transition: { staggerChildren: 0.15, delayChildren: 0 },
        },
      }}
      initial="hidden"
      animate="visible"
    >
      {/* IOC Distribution - Sized Pie Chart */}
      <motion.div variants={{ hidden: { opacity: 0, y: 20 }, visible: { opacity: 1, y: 0, transition: { duration: 0.5 } } }}>
        <SizedPieChart
          data={pieChartData}
          title="IOC Types Distribution"
          description="Breakdown by indicator type"
          className="h-full"
        />
      </motion.div>

      {/* Severity Breakdown - Vertical Bar Chart */}
      <motion.div variants={{ hidden: { opacity: 0, y: 20 }, visible: { opacity: 1, y: 0, transition: { duration: 0.5 } } }}>
        <BarChartMedium
          data={severityBarData}
          title="Severity Breakdown"
          height={280}
          showTimePeriod={false}
          colorScheme={Object.values(SEVERITY_COLORS)}
          className="h-full"
        />
      </motion.div>

      {/* Attack Frequency - Area Chart */}
      <motion.div variants={{ hidden: { opacity: 0, y: 20 }, visible: { opacity: 1, y: 0, transition: { duration: 0.5 } } }} className="md:col-span-2">
        <AttackFrequencyChart />
      </motion.div>

      {/* Top Feeds - Horizontal Bar Chart */}
      <motion.div variants={{ hidden: { opacity: 0, y: 20 }, visible: { opacity: 1, y: 0, transition: { duration: 0.5 } } }} className="md:col-span-2">
        <HorizontalBarMedium
          data={topFeedsData}
          title="Top Threat Feeds"
          height={300}
          colorScheme={['#5B14C5', '#9152EE', '#40E5D1', '#A840E8', '#4C86FF']}
          className="h-full"
        />
      </motion.div>
    </motion.div>
  )
}

export default function Page() {
  const { toast } = useToast()
  const [isCollecting, setIsCollecting] = useState(false)
  const [isSending, setIsSending] = useState(false)
  const [isGenerating, setIsGenerating] = useState(false)
  const [reportLimit, setReportLimit] = useState(50)

  const handleCollectFeeds = async () => {
    setIsCollecting(true)
    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/feeds/collect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret: 'socgen-feed-key' }),
      })
      const data = await response.json()
      toast({
        title: 'Success',
        description: data.status,
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to collect feeds',
        variant: 'destructive',
      })
    } finally {
      setIsCollecting(false)
    }
  }

  const handleSendEmail = async () => {
    setIsSending(true)
    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/email/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ severity_filter: 'High', limit: 50 }),
      })
      const data = await response.json()
      toast({
        title: 'Success',
        description: data.message,
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to send email',
        variant: 'destructive',
      })
    } finally {
      setIsSending(false)
    }
  }

  const handleGenerateReport = async () => {
    setIsGenerating(true)
    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/reports/generate?limit=${reportLimit}`, {
        method: 'POST',
      })
      const data = await response.json()
      window.location.href = `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/reports/download`
      toast({
        title: 'Success',
        description: data.message,
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to generate report',
        variant: 'destructive',
      })
    } finally {
      setIsGenerating(false)
    }
  }

  const [summaryStats, setSummaryStats] = useState<any>(null)
  
  useEffect(() => {
    const fetchSummaryStats = async () => {
      try {
        const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/summaries/stats`)
        setSummaryStats(await res.json())
      } catch (error) {
        console.error('Failed to fetch summary stats for alerts:', error)
      }
    }
    fetchSummaryStats()
    const interval = setInterval(fetchSummaryStats, 30000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="min-h-screen bg-background relative overflow-hidden">
      {/* Animated Background */}
      <div className="fixed inset-0 z-0">
        <EtherealShadow
          color="rgba(6, 182, 212, 0.15)"
          animation={{ scale: 60, speed: 40 }}
          noise={{ opacity: 0.5, scale: 1 }}
          sizing="fill"
        />
      </div>

      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-border/40 backdrop-blur-xl bg-background/70">
        <motion.div
          className="container mx-auto px-4 py-4"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: 'easeOut' }}
        >
          <div className="flex items-center justify-between">
            <motion.div className="flex items-center gap-3" whileHover={{ scale: 1.02 }}>
              <motion.div animate={{ rotate: 360 }} transition={{ duration: 8, repeat: Infinity, ease: 'linear' }}>
                <Shield className="h-8 w-8 text-primary drop-shadow-lg" />
              </motion.div>
              <div>
                <h1 className="text-2xl font-bold text-foreground">SOC Dashboard</h1>
                <p className="text-sm text-muted-foreground">Threat Intelligence & Security Monitoring</p>
              </div>
            </motion.div>
            <div className="flex gap-2">
              <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
                <Button
                  onClick={handleCollectFeeds}
                  disabled={isCollecting}
                  size="sm"
                  className="gap-2 bg-primary hover:bg-primary/90"
                >
                  <motion.div animate={isCollecting ? { rotate: 360 } : {}} transition={{ duration: 1, repeat: isCollecting ? Infinity : 0, ease: 'linear' }}>
                    <RefreshCw className="h-4 w-4" />
                  </motion.div>
                  {isCollecting ? 'Collecting...' : 'Collect Feeds'}
                </Button>
              </motion.div>
              <div className="flex items-center gap-1">
                <select
                  value={reportLimit}
                  onChange={(e) => setReportLimit(Number(e.target.value))}
                  className="h-8 rounded-md border border-input bg-transparent px-2 py-1 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                >
                  <option value={10}>10</option>
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
                <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
                  <Button
                    onClick={handleGenerateReport}
                    disabled={isGenerating}
                    size="sm"
                    variant="outline"
                    className="gap-2 bg-transparent"
                  >
                    <motion.div animate={isGenerating ? { scale: [1, 1.2, 1] } : {}} transition={{ duration: 0.8, repeat: isGenerating ? Infinity : 0 }}>
                      <Download className="h-4 w-4" />
                    </motion.div>
                    {isGenerating ? 'Generating...' : 'Report'}
                  </Button>
                </motion.div>
              </div>
              <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
                <Button
                  onClick={handleSendEmail}
                  disabled={isSending}
                  size="sm"
                  variant="outline"
                  className="gap-2 bg-transparent"
                >
                  <motion.div animate={isSending ? { y: [0, -4, 0] } : {}} transition={{ duration: 0.8, repeat: isSending ? Infinity : 0 }}>
                    <Mail className="h-4 w-4" />
                  </motion.div>
                  {isSending ? 'Sending...' : 'Email'}
                </Button>
              </motion.div>
            </div>
          </div>
        </motion.div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8 relative z-10">
        {/* Critical Alerts */}
        <motion.div
          className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <NeonAlert 
            severity="critical" 
            title="Critical Threats Detected" 
            count={summaryStats?.by_severity?.Critical || 0} 
          />
          <NeonAlert 
            severity="high" 
            title="High Severity IOCs" 
            count={summaryStats?.by_severity?.High || 0} 
          />
          <NeonAlert 
            severity="medium" 
            title="Medium Priority Alerts" 
            count={summaryStats?.by_severity?.Medium || 0} 
          />
        </motion.div>

        {/* Statistics */}
        <DashboardStats />

        {/* Main Tabs */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3, duration: 0.5 }}>
          <Tabs defaultValue="overview" className="mt-8">
            <TabsList className="grid w-full grid-cols-7 bg-secondary/50 backdrop-blur-sm border border-border/30">
              <TabsTrigger value="overview" className="flex items-center gap-2">
                <Activity className="h-4 w-4" />
                <span className="hidden sm:inline">Overview</span>
              </TabsTrigger>
              <TabsTrigger value="feeds" className="flex items-center gap-2">
                <TrendingUp className="h-4 w-4" />
                <span className="hidden sm:inline">Feeds</span>
              </TabsTrigger>
              <TabsTrigger value="iocs" className="flex items-center gap-2">
                <AlertCircle className="h-4 w-4" />
                <span className="hidden sm:inline">IOCs</span>
              </TabsTrigger>
              <TabsTrigger value="summaries" className="flex items-center gap-2">
                <Shield className="h-4 w-4" />
                <span className="hidden sm:inline">Summaries</span>
              </TabsTrigger>
              <TabsTrigger value="campaigns" className="flex items-center gap-2">
                <Target className="h-4 w-4" />
                <span className="hidden sm:inline">Campaigns</span>
              </TabsTrigger>
              <TabsTrigger value="predictions" className="flex items-center gap-2">
                <Brain className="h-4 w-4" />
                <span className="hidden sm:inline">Predictions</span>
              </TabsTrigger>
              <TabsTrigger value="graph" className="flex items-center gap-2">
                <Network className="h-4 w-4" />
                <span className="hidden sm:inline">Graph</span>
              </TabsTrigger>
            </TabsList>
            <TabsContent value="overview" className="mt-6 space-y-6">
              <OverviewTab />
            </TabsContent>
            <TabsContent value="feeds" className="mt-6">
              <FeedsList />
            </TabsContent>
            <TabsContent value="iocs" className="mt-6">
              <IOCTable />
            </TabsContent>
            <TabsContent value="summaries" className="mt-6">
              <SummariesList />
            </TabsContent>
            <TabsContent value="campaigns" className="mt-6">
              <CampaignView />
            </TabsContent>
            <TabsContent value="predictions" className="mt-6">
              <PredictionView />
            </TabsContent>
            <TabsContent value="graph" className="mt-6">
              <KnowledgeGraphView />
            </TabsContent>
          </Tabs>
        </motion.div>
      </main>
    </div>
  )
}
