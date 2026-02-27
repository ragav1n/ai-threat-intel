'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import {
  Brain,
  Shield,
  Target,
  ChevronRight,
  Loader2,
  Sparkles,
  TrendingUp,
  AlertTriangle,
} from 'lucide-react'

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

// Kill chain stages in order for the progress visualization
const KILL_CHAIN = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
]

const CONFIDENCE_COLORS: Record<string, string> = {
  high: 'text-red-400 bg-red-500/15 border-red-500/30',
  medium: 'text-yellow-400 bg-yellow-500/15 border-yellow-500/30',
  low: 'text-green-400 bg-green-500/15 border-green-500/30',
}

function getConfidenceLevel(c: number): string {
  if (c >= 0.7) return 'high'
  if (c >= 0.4) return 'medium'
  return 'low'
}

interface PredictionResult {
  campaign_id: string
  campaign_label: string
  current_stage: string
  predictions: Array<{
    tactic: string
    technique_id: string
    technique_name: string
    confidence: number
    reasoning: string
  }>
  defensive_recommendations: string[]
  model_used: string
  generated_at: string
}

interface PredictionStats {
  total_predictions: number
  unique_campaigns_predicted: number
  most_predicted_tactic: string | null
  avg_prediction_confidence: number
  tactic_distribution?: Record<string, number>
}

export default function PredictionView() {
  const [campaigns, setCampaigns] = useState<any[]>([])
  const [selectedCampaign, setSelectedCampaign] = useState<string | null>(null)
  const [prediction, setPrediction] = useState<PredictionResult | null>(null)
  const [stats, setStats] = useState<PredictionStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [predicting, setPredicting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [campRes, statsRes] = await Promise.all([
          fetch(`${API_URL}/api/campaigns?limit=20&sort_by=last_seen`),
          fetch(`${API_URL}/api/predict/stats`),
        ])
        const campData = await campRes.json()
        setCampaigns(campData.campaigns || [])
        if (statsRes.ok) setStats(await statsRes.json())
      } catch (err) {
        console.error('Failed to fetch data:', err)
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [])

  const runPrediction = async (campaignId: string) => {
    setSelectedCampaign(campaignId)
    setPredicting(true)
    setError(null)
    setPrediction(null)

    try {
      // First check for existing prediction history
      const historyRes = await fetch(`${API_URL}/api/predict/history/${campaignId}?limit=1`)
      if (historyRes.ok) {
        const historyData = await historyRes.json()
        if (historyData.predictions && historyData.predictions.length > 0) {
          setPrediction(historyData.predictions[0])
          setPredicting(false)
          return
        }
      }

      // No history, run a new prediction
      const res = await fetch(`${API_URL}/api/predict/campaign/${campaignId}`, {
        method: 'POST',
      })
      if (!res.ok) {
        const errData = await res.json()
        throw new Error(errData.detail || 'Prediction failed')
      }
      setPrediction(await res.json())
    } catch (err: any) {
      setError(err.message || 'Failed to run prediction')
    } finally {
      setPredicting(false)
    }
  }

  const getStageIndex = (stage: string): number => {
    const idx = KILL_CHAIN.findIndex((s) => s.toLowerCase() === stage.toLowerCase())
    return idx >= 0 ? idx : 0
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[...Array(3)].map((_, i) => (
            <Card key={i} className="p-6 h-28 animate-pulse bg-gradient-to-r from-muted to-muted/50" />
          ))}
        </div>
      </div>
    )
  }

  const container = {
    hidden: { opacity: 0 },
    visible: { opacity: 1, transition: { staggerChildren: 0.1 } },
  }
  const item = {
    hidden: { opacity: 0, y: 16 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.4 } },
  }

  return (
    <motion.div className="space-y-6" variants={container} initial="hidden" animate="visible">

      {/* Stats Cards */}
      <motion.div className="grid grid-cols-2 md:grid-cols-4 gap-4" variants={item}>
        <Card className="bg-card/80 backdrop-blur-sm border-border/30 hover:border-purple-500/40 transition-colors">
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-500/10">
                <Brain className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-foreground">{stats?.total_predictions ?? 0}</p>
                <p className="text-xs text-muted-foreground">Total Predictions</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/80 backdrop-blur-sm border-border/30 hover:border-cyan-500/40 transition-colors">
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyan-500/10">
                <Target className="h-5 w-5 text-cyan-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-foreground">{stats?.unique_campaigns_predicted ?? 0}</p>
                <p className="text-xs text-muted-foreground">Campaigns Predicted</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/80 backdrop-blur-sm border-border/30 hover:border-orange-500/40 transition-colors">
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-orange-500/10">
                <TrendingUp className="h-5 w-5 text-orange-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-foreground truncate max-w-[120px]">{stats?.most_predicted_tactic ?? '—'}</p>
                <p className="text-xs text-muted-foreground">Top Tactic</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/80 backdrop-blur-sm border-border/30 hover:border-green-500/40 transition-colors">
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-500/10">
                <Sparkles className="h-5 w-5 text-green-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-foreground">
                  {stats?.avg_prediction_confidence ? `${(stats.avg_prediction_confidence * 100).toFixed(0)}%` : '—'}
                </p>
                <p className="text-xs text-muted-foreground">Avg Confidence</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Campaign Selector */}
        <motion.div variants={item} className="lg:col-span-1">
          <Card className="bg-card/80 backdrop-blur-sm border-border/30">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-semibold flex items-center gap-2">
                <Target className="h-4 w-4 text-primary" />
                Select Campaign
              </CardTitle>
              <CardDescription>Choose a campaign to predict its next TTP</CardDescription>
            </CardHeader>
            <CardContent className="space-y-1.5 max-h-[500px] overflow-y-auto">
              {campaigns.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Target className="h-10 w-10 mx-auto mb-2 opacity-30" />
                  <p className="text-sm">No campaigns available</p>
                </div>
              ) : (
                campaigns.map((c: any) => (
                  <button
                    key={c.campaign_id}
                    onClick={() => runPrediction(c.campaign_id)}
                    className={`w-full text-left px-3 py-2.5 rounded-lg border transition-all ${
                      selectedCampaign === c.campaign_id
                        ? 'bg-primary/10 border-primary/40 ring-1 ring-primary/20'
                        : 'bg-secondary/20 border-border/30 hover:bg-secondary/40 hover:border-border/50'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-foreground truncate">{c.label}</span>
                      <ChevronRight className="h-3.5 w-3.5 text-muted-foreground shrink-0 ml-2" />
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-[10px] text-muted-foreground font-mono">{c.ioc_count} IOCs</span>
                      <span className="text-[10px] text-muted-foreground">
                        conf: {(c.avg_confidence * 100).toFixed(0)}%
                      </span>
                    </div>
                  </button>
                ))
              )}
            </CardContent>
          </Card>
        </motion.div>

        {/* Prediction Results */}
        <motion.div variants={item} className="lg:col-span-2">
          <Card className="bg-card/80 backdrop-blur-sm border-border/30 min-h-[400px]">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-semibold flex items-center gap-2">
                <Brain className="h-4 w-4 text-purple-400" />
                TTP Prediction
                {prediction && (
                  <Badge variant="outline" className="ml-2 text-[10px] font-mono text-purple-400 border-purple-500/30">
                    {prediction.model_used}
                  </Badge>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {predicting ? (
                <div className="flex flex-col items-center justify-center py-16">
                  <Loader2 className="h-8 w-8 text-purple-400 animate-spin mb-4" />
                  <p className="text-sm text-muted-foreground">Running agentic prediction pipeline...</p>
                  <p className="text-xs text-muted-foreground/60 mt-1">This involves 3 sequential LLM calls</p>
                </div>
              ) : error ? (
                <div className="flex flex-col items-center justify-center py-16">
                  <AlertTriangle className="h-8 w-8 text-red-400 mb-4" />
                  <p className="text-sm text-red-400">{error}</p>
                  <p className="text-xs text-muted-foreground mt-2">Make sure Ollama is running</p>
                </div>
              ) : prediction ? (
                <div className="space-y-5">
                  {/* Kill Chain Progress */}
                  <div>
                    <p className="text-xs text-muted-foreground mb-2">Current Attack Stage</p>
                    <div className="flex items-center gap-0.5 flex-wrap">
                      {KILL_CHAIN.map((stage, idx) => {
                        const currentIdx = getStageIndex(prediction.current_stage)
                        const isActive = idx <= currentIdx
                        const isCurrent = idx === currentIdx
                        return (
                          <div
                            key={stage}
                            className={`h-2 flex-1 min-w-[16px] rounded-sm transition-all ${
                              isCurrent
                                ? 'bg-red-500 ring-1 ring-red-400/50'
                                : isActive
                                ? 'bg-orange-500/60'
                                : 'bg-muted/40'
                            }`}
                            title={stage}
                          />
                        )
                      })}
                    </div>
                    <p className="text-sm font-semibold text-foreground mt-1.5">
                      {prediction.current_stage}
                    </p>
                  </div>

                  <Separator className="bg-border/30" />

                  {/* Predicted TTPs */}
                  <div>
                    <p className="text-xs text-muted-foreground mb-2">Predicted Next TTPs</p>
                    <div className="space-y-2.5">
                      {prediction.predictions.map((pred, idx) => {
                        const level = getConfidenceLevel(pred.confidence)
                        const colorClass = CONFIDENCE_COLORS[level]
                        return (
                          <div
                            key={idx}
                            className="px-3 py-2.5 rounded-lg border border-border/40 bg-secondary/20"
                          >
                            <div className="flex items-center justify-between mb-1">
                              <div className="flex items-center gap-2">
                                <Badge className={`${colorClass} border text-[10px] font-semibold px-2 py-0`}>
                                  {(pred.confidence * 100).toFixed(0)}%
                                </Badge>
                                <span className="text-sm font-medium text-foreground">{pred.tactic}</span>
                              </div>
                              <span className="text-xs font-mono text-muted-foreground">{pred.technique_id}</span>
                            </div>
                            <p className="text-xs text-foreground/80 font-medium">{pred.technique_name}</p>
                            {pred.reasoning && (
                              <p className="text-[11px] text-muted-foreground mt-1">{pred.reasoning}</p>
                            )}
                            {/* Confidence bar */}
                            <div className="mt-2 h-1 bg-muted/30 rounded-full overflow-hidden">
                              <motion.div
                                className={`h-full rounded-full ${
                                  level === 'high' ? 'bg-red-500' : level === 'medium' ? 'bg-yellow-500' : 'bg-green-500'
                                }`}
                                initial={{ width: 0 }}
                                animate={{ width: `${pred.confidence * 100}%` }}
                                transition={{ duration: 0.8, delay: idx * 0.2 }}
                              />
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>

                  {/* Defensive Recommendations */}
                  {prediction.defensive_recommendations.length > 0 && (
                    <>
                      <Separator className="bg-border/30" />
                      <div>
                        <p className="text-xs text-muted-foreground mb-2 flex items-center gap-1.5">
                          <Shield className="h-3 w-3" />
                          Defensive Recommendations
                        </p>
                        <div className="space-y-1.5">
                          {prediction.defensive_recommendations.map((rec, idx) => (
                            <div key={idx} className="flex items-start gap-2 text-xs">
                              <ChevronRight className="h-3 w-3 text-green-400 shrink-0 mt-0.5" />
                              <span className="text-foreground/80">{rec}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </>
                  )}

                  {/* Metadata */}
                  <div className="text-[10px] text-muted-foreground/50 pt-2">
                    Generated: {new Date(prediction.generated_at).toLocaleString()}
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-16">
                  <Brain className="h-12 w-12 text-muted-foreground/20 mb-4" />
                  <p className="text-sm text-muted-foreground">Select a campaign to predict its next TTP</p>
                  <p className="text-xs text-muted-foreground/60 mt-1">
                    The agentic pipeline will classify the attack stage and forecast the next move
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </motion.div>
  )
}
