'use client'

import React from "react"

import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import ReactMarkdown from 'react-markdown'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { SkeletonCard } from '@/components/ui/skeleton'
import { EmptyState } from '@/components/empty-state'
import { AlertCircle, Sparkles } from 'lucide-react'
import { useToast } from '@/hooks/use-toast'

export default function SummariesList() {
  const { toast } = useToast()
  const [summaries, setSummaries] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [newIOC, setNewIOC] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [severity, setSeverity] = useState<string>('')
  const [refreshKey, setRefreshKey] = useState(0)

  // Fetch summaries with polling for real-time updates
  useEffect(() => {
    const fetchSummaries = async () => {
      try {
        let url = `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/summaries?limit=50`
        if (severity) url += '&severity=' + severity

        const response = await fetch(url)
        const data = await response.json()
        setSummaries(data.summaries || [])
      } catch (error) {
        console.error('Failed to fetch summaries:', error)
      } finally {
        setLoading(false)
      }
    }
    fetchSummaries()

    // Poll every 15 seconds for real-time updates
    const interval = setInterval(fetchSummaries, 15000)
    return () => clearInterval(interval)
  }, [severity, refreshKey])

  const handleAnalyzeIOC = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newIOC.trim()) return

    setAnalyzing(true)
    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/summarize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ioc: newIOC }),
      })
      const data = await response.json()
      setSummaries([data, ...summaries])
      setNewIOC('')
      setRefreshKey(prev => prev + 1) // Trigger refresh for real-time update
      toast({
        title: 'Success',
        description: 'IOC analyzed successfully',
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to analyze IOC',
        variant: 'destructive',
      })
    } finally {
      setAnalyzing(false)
    }
  }

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

  return (
    <div className="space-y-6">
      {/* Analyze IOC Section */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <Card className="p-6 border-primary/30 bg-secondary/30 hover:border-primary/50 transition-colors">
          <div className="flex items-center gap-3 mb-4">
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
            >
              <Sparkles className="h-5 w-5 text-primary" />
            </motion.div>
            <h3 className="text-lg font-semibold text-foreground">Analyze New IOC</h3>
          </div>
          <form onSubmit={handleAnalyzeIOC} className="flex gap-2">
            <Input
              placeholder="Enter IOC (IP, domain, hash, or URL)..."
              value={newIOC}
              onChange={(e) => setNewIOC(e.target.value)}
              className="flex-1"
            />
            <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
              <Button disabled={analyzing} className="gap-2">
                <motion.div
                  animate={analyzing ? { rotate: 360 } : {}}
                  transition={{ duration: 1, repeat: analyzing ? Infinity : 0, ease: 'linear' }}
                >
                  <Sparkles className="h-4 w-4" />
                </motion.div>
                {analyzing ? 'Analyzing...' : 'Analyze'}
              </Button>
            </motion.div>
          </form>
        </Card>
      </motion.div>

      {/* Severity Filter */}
      <div className="flex gap-2">
        <Button
          variant={severity === '' ? 'default' : 'outline'}
          size="sm"
          onClick={() => setSeverity('')}
        >
          All
        </Button>
        {['Critical', 'High', 'Medium', 'Low'].map((sev) => (
          <Button
            key={sev}
            variant={severity === sev ? 'default' : 'outline'}
            size="sm"
            onClick={() => setSeverity(sev)}
          >
            {sev}
          </Button>
        ))}
      </div>

      {/* Summaries List */}
      <motion.div
        className="space-y-4"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.5, staggerChildren: 0.1 }}
      >
        {loading ? (
          <div className="grid grid-cols-1 gap-4">
            {[...Array(3)].map((_, i) => (
              <SkeletonCard key={i} />
            ))}
          </div>
        ) : summaries.length === 0 ? (
          <EmptyState
            type="no-data"
            title="No Threat Summaries Yet"
            description="Analyze IOCs to generate threat intelligence summaries. Start by entering an IOC above."
            action={{ label: 'Analyze Your First IOC', onClick: () => window.scrollTo({ top: 0, behavior: 'smooth' }) }}
          />
        ) : (
          summaries.map((summary, idx) => (
            <motion.div
              key={idx}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: idx * 0.08, duration: 0.5 }}
            >
              <motion.div
                whileHover={{ scale: 1.02, y: -5 }}
                transition={{ type: 'spring', stiffness: 400, damping: 25 }}
              >
                <Card className="p-6 border-border/50 hover:border-primary/50 transition-colors bg-card/50 backdrop-blur-sm border-border/30">
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <p className="text-sm text-muted-foreground mb-1">Analyzed IOC</p>
                      <p className="font-mono text-lg text-primary break-all">{summary.input}</p>
                    </div>
                    <Badge className={getSeverityColor(summary.severity)}>{summary.severity}</Badge>
                  </div>

                  <div className="space-y-4">
                    {/* Summary */}
                    <div>
                      <h4 className="font-semibold text-foreground mb-2">Threat Summary</h4>
                      <div className="text-sm text-muted-foreground prose prose-sm prose-invert max-w-none prose-headings:text-foreground prose-headings:font-semibold prose-headings:text-base prose-p:text-muted-foreground prose-strong:text-foreground prose-ul:text-muted-foreground prose-li:marker:text-primary">
                        <ReactMarkdown>{summary.summary}</ReactMarkdown>
                      </div>
                    </div>

                    {/* Enrichment */}
                    {summary.enrichment && (
                      <div>
                        <h4 className="font-semibold text-foreground mb-2">Enrichment</h4>
                        <p className="text-sm text-muted-foreground">{summary.enrichment}</p>
                      </div>
                    )}

                    {/* Enhanced MITRE ATT&CK TTPs (Phase 1 feature) */}
                    {summary.mitre_ttps && summary.mitre_ttps.length > 0 && (
                      <div>
                        <h4 className="font-semibold text-foreground mb-2">MITRE ATT&CK Techniques</h4>
                        <div className="flex flex-wrap gap-2">
                          {summary.mitre_ttps.map((ttp: any, tidx: number) => {
                            const confidence = typeof ttp.confidence === 'number'
                              ? Math.round(ttp.confidence * 100)
                              : ttp.confidence
                            const confidenceColor = confidence >= 80
                              ? 'text-green-400'
                              : confidence >= 50
                                ? 'text-yellow-400'
                                : 'text-orange-400'
                            return (
                              <div
                                key={tidx}
                                className="flex items-center gap-2 bg-secondary/50 border border-primary/30 rounded-lg px-3 py-2"
                              >
                                <Badge variant="outline" className="bg-primary/20 text-primary border-primary/30 font-mono">
                                  {ttp.technique_id}
                                </Badge>
                                <span className="text-sm text-foreground">{ttp.technique_name}</span>
                                {ttp.tactic && (
                                  <Badge variant="secondary" className="text-xs">
                                    {ttp.tactic}
                                  </Badge>
                                )}
                                {confidence && (
                                  <span className={`text-xs font-medium ${confidenceColor}`}>
                                    {confidence}%
                                  </span>
                                )}
                              </div>
                            )
                          })}
                        </div>
                      </div>
                    )}

                    {/* Legacy MITRE Tactics (fallback) */}
                    {!summary.mitre_ttps && summary.mitre_tactics && summary.mitre_tactics.length > 0 && (
                      <div>
                        <h4 className="font-semibold text-foreground mb-2">MITRE Tactics</h4>
                        <div className="flex flex-wrap gap-2">
                          {summary.mitre_tactics.map((tactic: string, tidx: number) => (
                            <Badge key={tidx} variant="outline" className="text-xs">
                              {tactic}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* RAG Context (Phase 1 feature) */}
                    {summary.rag_context && summary.rag_context.length > 0 && (
                      <div>
                        <h4 className="font-semibold text-foreground mb-2 text-sm">Retrieved Context</h4>
                        <div className="text-xs text-muted-foreground bg-secondary/30 rounded-lg p-2 max-h-20 overflow-y-auto">
                          {summary.rag_context.slice(0, 3).map((ctx: string, cidx: number) => (
                            <p key={cidx} className="truncate">{ctx}</p>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Recommendations */}
                    {summary.recommendations && summary.recommendations.length > 0 && (
                      <div>
                        <h4 className="font-semibold text-foreground mb-2">Recommendations</h4>
                        <ul className="text-sm text-muted-foreground space-y-1 list-disc list-inside">
                          {summary.recommendations.map((rec: string, ridx: number) => (
                            <li key={ridx} className="prose prose-sm prose-invert prose-p:inline prose-strong:text-foreground">
                              <ReactMarkdown components={{ p: ({ children }) => <span>{children}</span> }}>{rec}</ReactMarkdown>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Timestamp */}
                    <p className="text-xs text-muted-foreground">
                      {new Date(summary.timestamp).toLocaleString()}
                    </p>
                  </div>
                </Card>
              </motion.div>
            </motion.div>
          ))
        )}
      </motion.div>
    </div>
  )
}
