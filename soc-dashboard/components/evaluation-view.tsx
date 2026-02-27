'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import {
  FlaskConical,
  Target,
  TrendingUp,
  Timer,
  Loader2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  BarChart3,
  Gauge,
  Zap,
  Play,
  History,
} from 'lucide-react'

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

// ─── Color helpers ────────────────────────────────────────────
function scoreColor(score: number): string {
  if (score >= 0.9) return 'text-emerald-400'
  if (score >= 0.7) return 'text-green-400'
  if (score >= 0.5) return 'text-yellow-400'
  return 'text-red-400'
}

function scoreBg(score: number): string {
  if (score >= 0.9) return 'bg-emerald-500'
  if (score >= 0.7) return 'bg-green-500'
  if (score >= 0.5) return 'bg-yellow-500'
  return 'bg-red-500'
}

function scoreBadge(score: number): string {
  if (score >= 0.9) return 'text-emerald-400 bg-emerald-500/15 border-emerald-500/30'
  if (score >= 0.7) return 'text-green-400 bg-green-500/15 border-green-500/30'
  if (score >= 0.5) return 'text-yellow-400 bg-yellow-500/15 border-yellow-500/30'
  return 'text-red-400 bg-red-500/15 border-red-500/30'
}

// ─── Interfaces ───────────────────────────────────────────────
interface TypeMetrics {
  ioc_type: string
  true_positives: number
  false_positives: number
  false_negatives: number
  precision: number
  recall: number
  f1: number
  avg_tp_confidence: number
  avg_fp_confidence: number
}

interface Metrics {
  total_samples: number
  total_expected: number
  total_extracted: number
  true_positives: number
  false_positives: number
  false_negatives: number
  precision: number
  recall: number
  f1: number
  avg_tp_confidence: number
  avg_fp_confidence: number
  per_type: Record<string, TypeMetrics>
  category_accuracy: Record<string, number>
}

interface BenchmarkStage {
  stage: string
  count: number
  mean_ms: number
  median_ms: number
  p95_ms: number
  p99_ms: number
  min_ms: number
  max_ms: number
}

interface Benchmark {
  total_samples: number
  total_time_ms: number
  throughput_samples_per_sec: number
  stages: Record<string, BenchmarkStage>
}

interface EvalResult {
  report_id: string
  timestamp: string
  pipeline_version: string
  dataset_summary: {
    total_samples: number
    total_expected_iocs: number
    category_counts: Record<string, number>
    ioc_type_counts: Record<string, number>
  }
  metrics: Metrics
  benchmark: Benchmark
}

interface HistoryItem {
  report_id: string
  timestamp: string
  pipeline_version: string
  metrics: { precision: number; recall: number; f1: number; true_positives: number; false_positives: number; false_negatives: number }
  benchmark?: { total_time_ms: number; throughput_samples_per_sec: number }
}

// ─── Component ────────────────────────────────────────────────
export default function EvaluationView() {
  const [result, setResult] = useState<EvalResult | null>(null)
  const [history, setHistory] = useState<HistoryItem[]>([])
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const fetchData = async () => {
    try {
      const [resLatest, resHistory] = await Promise.all([
        fetch(`${API_URL}/api/evaluation/results`),
        fetch(`${API_URL}/api/evaluation/history?limit=10`),
      ])
      if (resLatest.ok) setResult(await resLatest.json())
      if (resHistory.ok) {
        const hd = await resHistory.json()
        setHistory(hd.evaluations || [])
      }
    } catch (err) {
      console.error('Failed to load evaluation data:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchData() }, [])

  const runEvaluation = async () => {
    setRunning(true)
    setError(null)
    try {
      const res = await fetch(`${API_URL}/api/evaluation/run`, { method: 'POST' })
      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.detail || 'Evaluation failed')
      }
      const data = await res.json()
      setResult(data)
      fetchData()
    } catch (err: any) {
      setError(err.message || 'Failed to run evaluation')
    } finally {
      setRunning(false)
    }
  }

  // ─── Loading skeleton ────────────────────
  if (loading) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <Card key={i} className="p-6 h-28 animate-pulse bg-gradient-to-r from-muted to-muted/50" />
          ))}
        </div>
      </div>
    )
  }

  const container = {
    hidden: { opacity: 0 },
    visible: { opacity: 1, transition: { staggerChildren: 0.08 } },
  }
  const item = {
    hidden: { opacity: 0, y: 16 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.4 } },
  }

  const metrics = result?.metrics
  const bench = result?.benchmark
  const perTypeArr = metrics ? Object.values(metrics.per_type).sort((a, b) => b.f1 - a.f1) : []

  return (
    <motion.div className="space-y-6" variants={container} initial="hidden" animate="visible">

      {/* ── Top Stat Cards ────────────────────────── */}
      <motion.div className="grid grid-cols-2 md:grid-cols-5 gap-4" variants={item}>
        <Card className="bg-card/80 backdrop-blur-sm border-border/30 hover:border-emerald-500/40 transition-colors">
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-emerald-500/10">
                <FlaskConical className="h-5 w-5 text-emerald-400" />
              </div>
              <div>
                <p className={`text-2xl font-bold ${metrics ? scoreColor(metrics.f1) : 'text-foreground'}`}>
                  {metrics ? `${(metrics.f1 * 100).toFixed(1)}%` : '—'}
                </p>
                <p className="text-xs text-muted-foreground">F1 Score</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/80 backdrop-blur-sm border-border/30 hover:border-blue-500/40 transition-colors">
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/10">
                <Target className="h-5 w-5 text-blue-400" />
              </div>
              <div>
                <p className={`text-2xl font-bold ${metrics ? scoreColor(metrics.precision) : 'text-foreground'}`}>
                  {metrics ? `${(metrics.precision * 100).toFixed(1)}%` : '—'}
                </p>
                <p className="text-xs text-muted-foreground">Precision</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/80 backdrop-blur-sm border-border/30 hover:border-purple-500/40 transition-colors">
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-500/10">
                <TrendingUp className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <p className={`text-2xl font-bold ${metrics ? scoreColor(metrics.recall) : 'text-foreground'}`}>
                  {metrics ? `${(metrics.recall * 100).toFixed(1)}%` : '—'}
                </p>
                <p className="text-xs text-muted-foreground">Recall</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/80 backdrop-blur-sm border-border/30 hover:border-orange-500/40 transition-colors">
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-orange-500/10">
                <Zap className="h-5 w-5 text-orange-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-foreground">
                  {bench ? `${bench.throughput_samples_per_sec.toFixed(0)}` : '—'}
                </p>
                <p className="text-xs text-muted-foreground">Samples/sec</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/80 backdrop-blur-sm border-border/30 hover:border-cyan-500/40 transition-colors">
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyan-500/10">
                <Gauge className="h-5 w-5 text-cyan-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-foreground">
                  {metrics ? metrics.total_samples : '—'}
                </p>
                <p className="text-xs text-muted-foreground">Test Samples</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* ── Run Button ─────────────────────────── */}
      <motion.div variants={item} className="flex items-center gap-4">
        <Button
          onClick={runEvaluation}
          disabled={running}
          className="bg-emerald-600 hover:bg-emerald-700 text-white"
        >
          {running ? (
            <><Loader2 className="h-4 w-4 animate-spin mr-2" /> Running Evaluation...</>
          ) : (
            <><Play className="h-4 w-4 mr-2" /> Run Evaluation</>
          )}
        </Button>
        {error && (
          <span className="text-sm text-red-400 flex items-center gap-1">
            <AlertTriangle className="h-3.5 w-3.5" /> {error}
          </span>
        )}
        {result && (
          <span className="text-xs text-muted-foreground">
            Last run: {new Date(result.timestamp).toLocaleString()}
          </span>
        )}
      </motion.div>

      {metrics && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* ── Confusion Matrix ────────────────── */}
          <motion.div variants={item} className="lg:col-span-1">
            <Card className="bg-card/80 backdrop-blur-sm border-border/30">
              <CardHeader className="pb-3">
                <CardTitle className="text-base font-semibold flex items-center gap-2">
                  <BarChart3 className="h-4 w-4 text-primary" />
                  Confusion Summary
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-3 gap-3">
                  <div className="text-center p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                    <CheckCircle2 className="h-5 w-5 text-emerald-400 mx-auto mb-1" />
                    <p className="text-2xl font-bold text-emerald-400">{metrics.true_positives}</p>
                    <p className="text-[10px] text-muted-foreground">True Positives</p>
                  </div>
                  <div className="text-center p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                    <XCircle className="h-5 w-5 text-red-400 mx-auto mb-1" />
                    <p className="text-2xl font-bold text-red-400">{metrics.false_positives}</p>
                    <p className="text-[10px] text-muted-foreground">False Positives</p>
                  </div>
                  <div className="text-center p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
                    <AlertTriangle className="h-5 w-5 text-yellow-400 mx-auto mb-1" />
                    <p className="text-2xl font-bold text-yellow-400">{metrics.false_negatives}</p>
                    <p className="text-[10px] text-muted-foreground">False Negatives</p>
                  </div>
                </div>

                <Separator className="bg-border/30" />

                {/* Confidence Calibration */}
                <div>
                  <p className="text-xs text-muted-foreground mb-2">Confidence Calibration</p>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-emerald-400">Avg TP Confidence</span>
                      <span className="font-mono font-semibold text-foreground">
                        {(metrics.avg_tp_confidence * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="h-1.5 bg-muted/30 rounded-full overflow-hidden">
                      <motion.div
                        className="h-full bg-emerald-500 rounded-full"
                        initial={{ width: 0 }}
                        animate={{ width: `${metrics.avg_tp_confidence * 100}%` }}
                        transition={{ duration: 1 }}
                      />
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-red-400">Avg FP Confidence</span>
                      <span className="font-mono font-semibold text-foreground">
                        {(metrics.avg_fp_confidence * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="h-1.5 bg-muted/30 rounded-full overflow-hidden">
                      <motion.div
                        className="h-full bg-red-500 rounded-full"
                        initial={{ width: 0 }}
                        animate={{ width: `${metrics.avg_fp_confidence * 100}%` }}
                        transition={{ duration: 1, delay: 0.2 }}
                      />
                    </div>
                  </div>
                </div>

                <Separator className="bg-border/30" />

                {/* Category Accuracy */}
                <div>
                  <p className="text-xs text-muted-foreground mb-2">Category Accuracy</p>
                  <div className="space-y-1.5">
                    {Object.entries(metrics.category_accuracy).map(([cat, acc]) => (
                      <div key={cat} className="flex items-center justify-between text-xs">
                        <span className="text-foreground/80 capitalize">{cat.replace('_', ' ')}</span>
                        <Badge className={`${scoreBadge(acc)} border text-[10px] px-2 py-0`}>
                          {(acc * 100).toFixed(0)}%
                        </Badge>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>

          {/* ── Per-Type Breakdown ──────────────── */}
          <motion.div variants={item} className="lg:col-span-2">
            <Card className="bg-card/80 backdrop-blur-sm border-border/30">
              <CardHeader className="pb-3">
                <CardTitle className="text-base font-semibold flex items-center gap-2">
                  <FlaskConical className="h-4 w-4 text-emerald-400" />
                  Per-Type Performance
                </CardTitle>
                <CardDescription>Extraction metrics disaggregated by IOC type</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {/* Table header */}
                  <div className="grid grid-cols-7 gap-2 text-[10px] text-muted-foreground font-medium px-3 pb-1">
                    <span className="col-span-1">Type</span>
                    <span className="text-center">TP</span>
                    <span className="text-center">FP</span>
                    <span className="text-center">FN</span>
                    <span className="text-center">Precision</span>
                    <span className="text-center">Recall</span>
                    <span className="text-center">F1</span>
                  </div>

                  {perTypeArr.map((tm, idx) => (
                    <motion.div
                      key={tm.ioc_type}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.05 }}
                      className="grid grid-cols-7 gap-2 items-center px-3 py-2 rounded-lg border border-border/30 bg-secondary/20"
                    >
                      <span className="text-xs font-semibold text-foreground uppercase tracking-wide col-span-1">
                        {tm.ioc_type}
                      </span>
                      <span className="text-center text-xs text-emerald-400 font-mono">{tm.true_positives}</span>
                      <span className="text-center text-xs text-red-400 font-mono">{tm.false_positives}</span>
                      <span className="text-center text-xs text-yellow-400 font-mono">{tm.false_negatives}</span>
                      <div className="text-center">
                        <Badge className={`${scoreBadge(tm.precision)} border text-[10px] px-1.5 py-0`}>
                          {(tm.precision * 100).toFixed(0)}%
                        </Badge>
                      </div>
                      <div className="text-center">
                        <Badge className={`${scoreBadge(tm.recall)} border text-[10px] px-1.5 py-0`}>
                          {(tm.recall * 100).toFixed(0)}%
                        </Badge>
                      </div>
                      <div className="text-center">
                        <Badge className={`${scoreBadge(tm.f1)} border text-[10px] px-1.5 py-0 font-bold`}>
                          {(tm.f1 * 100).toFixed(0)}%
                        </Badge>
                      </div>
                    </motion.div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </div>
      )}

      {/* ── Latency Benchmarks ───────────────── */}
      {bench && (
        <motion.div variants={item}>
          <Card className="bg-card/80 backdrop-blur-sm border-border/30">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-semibold flex items-center gap-2">
                <Timer className="h-4 w-4 text-orange-400" />
                Latency Benchmarks
              </CardTitle>
              <CardDescription>
                {bench.total_samples} samples · {bench.total_time_ms.toFixed(0)}ms total ·{' '}
                {bench.throughput_samples_per_sec.toFixed(1)} samples/sec
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {Object.values(bench.stages).map((stage, idx) => {
                  const maxMs = Math.max(...Object.values(bench.stages).map((s) => s.p95_ms), 1)
                  return (
                    <motion.div
                      key={stage.stage}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: idx * 0.1 }}
                      className="p-4 rounded-lg border border-border/30 bg-secondary/20"
                    >
                      <div className="flex items-center justify-between mb-3">
                        <span className="text-sm font-medium text-foreground capitalize">
                          {stage.stage.replace('_', ' ')}
                        </span>
                        <span className="text-xs text-muted-foreground font-mono">
                          n={stage.count}
                        </span>
                      </div>
                      <div className="space-y-2">
                        {[
                          { label: 'Mean', value: stage.mean_ms },
                          { label: 'Median', value: stage.median_ms },
                          { label: 'P95', value: stage.p95_ms },
                          { label: 'P99', value: stage.p99_ms },
                        ].map((m) => (
                          <div key={m.label} className="space-y-0.5">
                            <div className="flex items-center justify-between text-[11px]">
                              <span className="text-muted-foreground">{m.label}</span>
                              <span className="font-mono text-foreground">{m.value.toFixed(2)}ms</span>
                            </div>
                            <div className="h-1 bg-muted/30 rounded-full overflow-hidden">
                              <motion.div
                                className="h-full bg-orange-500 rounded-full"
                                initial={{ width: 0 }}
                                animate={{ width: `${Math.min((m.value / maxMs) * 100, 100)}%` }}
                                transition={{ duration: 0.8, delay: idx * 0.1 }}
                              />
                            </div>
                          </div>
                        ))}
                      </div>
                    </motion.div>
                  )
                })}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* ── Evaluation History ──────────────── */}
      {history.length > 0 && (
        <motion.div variants={item}>
          <Card className="bg-card/80 backdrop-blur-sm border-border/30">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-semibold flex items-center gap-2">
                <History className="h-4 w-4 text-cyan-400" />
                Evaluation History
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <div className="grid grid-cols-7 gap-2 text-[10px] text-muted-foreground font-medium px-3 pb-1">
                  <span className="col-span-2">Timestamp</span>
                  <span className="text-center">Version</span>
                  <span className="text-center">Precision</span>
                  <span className="text-center">Recall</span>
                  <span className="text-center">F1</span>
                  <span className="text-center">Throughput</span>
                </div>
                {history.map((h, idx) => (
                  <motion.div
                    key={h.report_id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.04 }}
                    className={`grid grid-cols-7 gap-2 items-center px-3 py-2 rounded-lg border transition-colors ${
                      idx === 0
                        ? 'border-emerald-500/30 bg-emerald-500/5'
                        : 'border-border/30 bg-secondary/20'
                    }`}
                  >
                    <span className="text-xs text-foreground/80 col-span-2 truncate">
                      {new Date(h.timestamp).toLocaleDateString()} {new Date(h.timestamp).toLocaleTimeString()}
                    </span>
                    <span className="text-center text-[10px] font-mono text-muted-foreground">{h.pipeline_version}</span>
                    <div className="text-center">
                      <span className={`text-xs font-mono ${scoreColor(h.metrics.precision)}`}>
                        {(h.metrics.precision * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="text-center">
                      <span className={`text-xs font-mono ${scoreColor(h.metrics.recall)}`}>
                        {(h.metrics.recall * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="text-center">
                      <Badge className={`${scoreBadge(h.metrics.f1)} border text-[10px] px-1.5 py-0`}>
                        {(h.metrics.f1 * 100).toFixed(1)}%
                      </Badge>
                    </div>
                    <div className="text-center">
                      <span className="text-xs font-mono text-foreground">
                        {h.benchmark?.throughput_samples_per_sec?.toFixed(0) ?? '—'}/s
                      </span>
                    </div>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* ── Empty state ────────────────────── */}
      {!metrics && !running && (
        <motion.div variants={item}>
          <Card className="bg-card/80 backdrop-blur-sm border-border/30">
            <CardContent className="flex flex-col items-center justify-center py-16">
              <FlaskConical className="h-12 w-12 text-muted-foreground/20 mb-4" />
              <p className="text-sm text-muted-foreground">No evaluation results yet</p>
              <p className="text-xs text-muted-foreground/60 mt-1">
                Click &quot;Run Evaluation&quot; to measure extraction accuracy against the ground-truth dataset
              </p>
            </CardContent>
          </Card>
        </motion.div>
      )}
    </motion.div>
  )
}
