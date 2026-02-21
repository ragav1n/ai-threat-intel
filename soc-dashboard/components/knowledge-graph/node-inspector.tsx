"use client"

import { useState, useEffect } from "react"
import { motion } from "framer-motion"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { X, Shield, Globe, Terminal, Activity, Calendar, Award } from "lucide-react"

interface NodeInspectorProps {
  nodeId: string
  onClose: () => void
}

export default function NodeInspector({ nodeId, onClose }: NodeInspectorProps) {
  const [details, setDetails] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Re-fetch guard: don't fetch if we already have the same node loaded
    if (details?.id === nodeId) return

    const fetchDetails = async () => {
      setLoading(true)
      try {
        const res = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/knowledge-graph/node?node=${encodeURIComponent(nodeId)}`
        )
        const data = await res.json()
        console.log("Inspector Details for node:", nodeId, data)
        setDetails(data)
      } catch (error) {
        console.error("Failed to fetch node details:", error)
      } finally {
        setLoading(false)
      }
    }
    fetchDetails()
  }, [nodeId])

  const safeFormatDate = (dateStr: string | null) => {
    if (!dateStr) return "N/A"
    try {
      // Handle the +00:00 suffix which can be tricky in some JS engines
      const date = new Date(dateStr.replace("+00:00", "Z"))
      if (isNaN(date.getTime())) return "Unknown Date"
      return date.toLocaleString()
    } catch (e) {
      return "Invalid Date"
    }
  }

  const getReliabilityLabel = (conf: number) => {
    if (conf >= 0.9) return { label: "High Confidence", color: "bg-green-500/20 text-green-400" }
    if (conf >= 0.6) return { label: "Corroborated", color: "bg-blue-500/20 text-blue-400" }
    return { label: "Emerging", color: "bg-yellow-500/20 text-yellow-400" }
  }

  const reliability = details ? getReliabilityLabel(details.confidence) : null

  return (
    <motion.div
      initial={{ x: 400, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: 400, opacity: 0 }}
      className="absolute top-0 right-0 w-96 h-full z-30"
    >
      <Card className="h-full bg-background/80 backdrop-blur-2xl border-l border-border/40 shadow-2xl flex flex-col">
        {/* Header */}
        <div className="p-6 border-b border-border/40 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Shield className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h2 className="text-lg font-bold leading-none mb-1">Node Inspector</h2>
              <p className="text-xs text-muted-foreground font-mono">ID: {nodeId.substring(0, 20)}...</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 hover:bg-muted rounded-md transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-8">
          {loading ? (
            <div className="space-y-6">
              <Skeleton className="h-24 w-full bg-muted/50" />
              <Skeleton className="h-40 w-full bg-muted/50" />
              <Skeleton className="h-32 w-full bg-muted/50" />
            </div>
          ) : (
            <>
              {/* Score Overview */}
              <div className="space-y-4">
                <div className="flex items-end justify-between">
                  <span className="text-sm font-bold uppercase tracking-wider text-muted-foreground">
                    Confidence Matrix
                  </span>
                  <Badge className={reliability?.color}>
                    {reliability?.label}
                  </Badge>
                </div>
                <div className="p-6 rounded-2xl bg-black/30 border border-primary/20 flex flex-col items-center gap-2">
                  <div className="text-5xl font-black text-primary drop-shadow-[0_0_15px_rgba(6,182,212,0.5)]">
                    {(details.confidence * 100).toFixed(0)}%
                  </div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-[0.2em] font-bold">
                    Bayesian Fused Score
                  </div>
                </div>
              </div>

              {/* Attributes */}
              <div className="space-y-4">
                <h3 className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                  <Activity className="h-4 w-4" /> Attributes
                </h3>
                <div className="grid grid-cols-2 gap-3">
                  <div className="p-3 rounded-xl bg-muted/30 border border-border/40">
                    <div className="text-[10px] text-muted-foreground uppercase mb-1">Type</div>
                    <div className="text-sm font-bold text-primary capitalize">{details.type}</div>
                  </div>
                  <div className="p-3 rounded-xl bg-muted/30 border border-border/40">
                    <div className="text-[10px] text-muted-foreground uppercase mb-1">Status</div>
                    <div className="text-sm font-bold text-white">
                      {details.reviewed ? "Verified" : "Crowdsourced"}
                    </div>
                  </div>
                </div>
              </div>

              {/* Provenance (The "Who") */}
              <div className="space-y-4">
                <h3 className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                  <Award className="h-4 w-4" /> Provenance (Admiralty)
                </h3>
                <div className="space-y-2">
                  {details.provenance && details.provenance.length > 0 ? (
                    details.provenance.map((source: string) => (
                      <div
                        key={source}
                        className="flex items-center justify-between p-3 rounded-xl bg-primary/5 border border-primary/10"
                      >
                        <div className="flex items-center gap-2">
                          <Globe className="h-4 w-4 text-primary" />
                          <span className="text-sm font-medium">{source}</span>
                        </div>
                        <Badge variant="outline" className="text-[10px] border-primary/20 bg-primary/20 text-primary">
                          VOUCHED
                        </Badge>
                      </div>
                    ))
                  ) : (
                    <p className="text-sm text-muted-foreground italic">No source metadata available.</p>
                  )}
                </div>
              </div>

              {/* Timeline */}
              <div className="space-y-4">
                <h3 className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                  <Calendar className="h-4 w-4" /> Detection Lifecycle
                </h3>
                <div className="space-y-4 border-l-2 border-muted pl-4 ml-1">
                  <div className="relative">
                    <div className="absolute -left-[21px] top-1 w-3 h-3 rounded-full bg-primary" />
                    <div className="text-[10px] text-muted-foreground uppercase">Last Seen</div>
                    <div className="text-sm font-medium">
                      {safeFormatDate(details.last_seen)}
                    </div>
                  </div>
                  <div className="relative opacity-60">
                    <div className="absolute -left-[21px] top-1 w-3 h-3 rounded-full bg-muted-foreground" />
                    <div className="text-[10px] text-muted-foreground uppercase">First Ingested</div>
                    <div className="text-sm font-medium">
                      {safeFormatDate(details.first_seen)}
                    </div>
                  </div>
                </div>
              </div>
            </>
          )}
        </div>
      </Card>
    </motion.div>
  )
}
