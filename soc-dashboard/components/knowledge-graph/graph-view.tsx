"use client"

import { useState, useMemo, useEffect, useRef } from "react"
import dynamic from "next/dynamic"
import { motion, AnimatePresence } from "framer-motion"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Network, Search, RefreshCw, Layers, ZoomIn } from "lucide-react"
import { Input } from "@/components/ui/input"
import NodeInspector from "@/components/knowledge-graph/node-inspector"

// Dynamic import for 2D Graph to avoid SSR issues
const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), {
  ssr: false,
  loading: () => (
    <div className="w-full h-[600px] flex items-center justify-center bg-black/20 rounded-xl border border-border/50">
      <div className="flex flex-col items-center gap-4">
        <RefreshCw className="h-10 w-10 animate-spin text-primary/50" />
        <p className="text-muted-foreground font-mono">Initializing Neural Viewport...</p>
      </div>
    </div>
  ),
})

const TYPE_COLORS: Record<string, string> = {
  ip: "#06b6d4",
  domain: "#f59e0b",
  md5: "#ef4444",
  sha256: "#10b981",
  url: "#8b5cf6",
  email: "#6366f1",
  cve: "#f43f5e",
  unknown: "#6b7280",
}

export default function KnowledgeGraphView() {
  const [data, setData] = useState<{ nodes: any[]; links: any[] }>({ nodes: [], links: [] })
  const [loading, setLoading] = useState(true)
  const [selectedNode, setSelectedNode] = useState<string | null>(null)
  const [searchTerm, setSearchTerm] = useState("")
  const [minConfidence, setMinConfidence] = useState(0.3)
  const graphRef = useRef<any>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 })

  // Handle auto-resize
  useEffect(() => {
    if (containerRef.current) {
      const resizeObserver = new ResizeObserver((entries) => {
        for (const entry of entries) {
          setDimensions({
            width: entry.contentRect.width,
            height: entry.contentRect.height,
          })
        }
      })
      resizeObserver.observe(containerRef.current)
      return () => resizeObserver.disconnect()
    }
  }, [])

  useEffect(() => {
    fetchGraph()
  }, [minConfidence])

  const fetchGraph = async () => {
    setLoading(true)
    try {
      const res = await fetch(
        `${
          process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"
        }/api/knowledge-graph?limit=300&min_confidence=${minConfidence}`
      )
      const graphData = await res.json()
      
      const formatted = {
        nodes: graphData.nodes.map((n: any) => ({
          id: n.data.id,
          name: n.data.id,
          type: n.data.type,
          val: (n.data.confidence || 0.5) * 5 + 1, // Node size for 3D
          confidence: n.data.confidence,
          color: TYPE_COLORS[n.data.type] || "#6b7280"
        })),
        links: graphData.edges.map((e: any) => ({
          source: e.data.source,
          target: e.data.target,
          type: e.data.type,
          weight: e.data.weight,
        })),
      }
      setData(formatted)
    } catch (error) {
      console.error("Failed to fetch graph:", error)
    } finally {
      setLoading(false)
    }
  }

  const filteredData = useMemo(() => {
    if (!searchTerm) return data
    const term = searchTerm.toLowerCase()
    return {
      nodes: data.nodes.filter((n) => n.id.toLowerCase().includes(term)),
      links: data.links, 
    }
  }, [data, searchTerm])

  const handleNodeClick = (node: any) => {
    setSelectedNode(node.id)
    if (graphRef.current) {
      // Improved zoom interaction
      graphRef.current.centerAt(node.x, node.y, 1000)
      graphRef.current.zoom(4, 1000)
    }
  }

  // Configure forces for better spacing
  useEffect(() => {
    if (graphRef.current) {
      const fg = graphRef.current;
      // Suggested repulsion strength
      fg.d3Force('charge', (window as any).d3?.forceManyBody().strength(-40));
      // Suggested link distance
      fg.d3Force('link').distance(40);
      // Centering and gravitational pull towards middle
      fg.d3Force('center', (window as any).d3?.forceCenter());
      fg.d3Force('x', (window as any).d3?.forceX().strength(0.08));
      fg.d3Force('y', (window as any).d3?.forceY().strength(0.08));
      // Suggested collision radius
      fg.d3Force('collide', (window as any).d3?.forceCollide(10));
    }
  }, [data]);

  return (
    <div className="relative w-full h-[700px] flex flex-col gap-4">
      {/* Controls Overlay */}
      <div className="absolute top-4 left-4 z-10 flex flex-col gap-3 w-80">
        <Card className="p-4 bg-background/40 backdrop-blur-2xl border-white/10 shadow-3xl">
          <div className="flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-primary font-mono text-xs font-bold uppercase tracking-widest">
                <Network className="h-4 w-4 fill-primary/20" />
                <span>Threat Network</span>
              </div>
              <Badge className="bg-primary/20 text-primary border-primary/30 text-[9px]">
                ACCELERATED 2D
              </Badge>
            </div>

            <div className="space-y-2">
              <div className="relative">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground/60" />
                <Input
                  placeholder="Locate indicator..."
                  className="pl-9 h-9 bg-black/40 border-white/5 focus-visible:ring-primary/50 text-xs font-mono"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
            </div>

            <div className="space-y-3 p-2 bg-white/5 rounded-lg border border-white/5">
              <div className="flex items-center justify-between text-[10px] text-muted-foreground uppercase font-black tracking-widest">
                <span>Filter Confidence</span>
                <span className="text-primary">{(minConfidence * 100).toFixed(0)}%</span>
              </div>
              <input
                type="range"
                min="0"
                max="1"
                step="0.05"
                value={minConfidence}
                onChange={(e) => setMinConfidence(parseFloat(e.target.value))}
                className="w-full accent-primary h-1 bg-white/10 rounded-lg appearance-none cursor-pointer"
              />
            </div>
          </div>
        </Card>

        {/* Legend */}
        <Card className="p-4 bg-background/40 backdrop-blur-2xl border-white/10 text-[10px] font-mono tracking-tighter">
          <div className="grid grid-cols-2 gap-y-2 gap-x-4">
            {Object.entries(TYPE_COLORS).map(([type, color]) => (
              <div key={type} className="flex items-center gap-2 group cursor-default">
                <div 
                   className="w-2 h-2 rounded-full shadow-[0_0_8px_rgba(0,0,0,0.5)] transition-transform group-hover:scale-125" 
                   style={{ backgroundColor: color, boxShadow: `0 0 10px ${color}44` }} 
                />
                <span className="text-muted-foreground group-hover:text-foreground transition-colors uppercase">{type}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Main Graph Canvas */}
      <Card ref={containerRef} className="flex-1 relative overflow-hidden bg-[#020617] border-white/5 group shadow-inner">
        <ForceGraph2D
          ref={graphRef}
          width={dimensions.width}
          height={dimensions.height}
          graphData={filteredData}
          nodeLabel={(node: any) => `${node.id}\nConfidence: ${(node.confidence * 100).toFixed(1)}%`}
          nodeColor="color"
          nodeRelSize={5}
          linkWidth={1.5}
          linkColor={() => "rgba(255,255,255,0.12)"}
          backgroundColor="#020617"
          onNodeClick={handleNodeClick}
          enableNodeDrag={true}
          warmupTicks={200}    // Runs simulation offscreen first for instant layout
          cooldownTicks={0}    // Stops animating once stable for performance
          nodeCanvasObject={(node: any, ctx: CanvasRenderingContext2D, globalScale) => {
            const label = node.id;
            const size = node.val || 5;
            
            // Simplified circle rendering for massive performance
            ctx.beginPath();
            ctx.arc(node.x, node.y, size, 0, 2 * Math.PI, false);
            ctx.fillStyle = node.color || "#6b7280";
            ctx.fill();
            
            // Optional: Draw text if zoomed in significantly
            if (globalScale > 8) {
              const fontSize = 12 / globalScale;
              ctx.font = `${fontSize}px Sans-Serif`;
              ctx.textAlign = 'center';
              ctx.textBaseline = 'middle';
              ctx.fillText(label, node.x, node.y + size + 2);
            }
          }}
          nodeCanvasObjectMode={() => "replace"}
          d3AlphaDecay={0.02}
          d3VelocityDecay={0.3}
          onEngineStop={() => graphRef.current?.zoomToFit(600, 100)}
        />
        
        {loading && (
          <div className="absolute inset-0 flex items-center justify-center bg-[#020617]/80 backdrop-blur-md z-20">
            <div className="flex flex-col items-center gap-6">
              <div className="relative">
                <div className="absolute inset-0 blur-2xl bg-primary/30 animate-pulse" />
                <RefreshCw className="h-12 w-12 animate-spin text-primary relative" />
              </div>
              <div className="space-y-1 text-center">
                <p className="text-primary font-mono font-bold tracking-[0.3em] uppercase text-xs">Syncing Nodes</p>
                <div className="flex gap-1 justify-center">
                  <div className="w-1.5 h-1.5 bg-primary/40 rounded-full animate-bounce [animation-delay:-0.3s]" />
                  <div className="w-1.5 h-1.5 bg-primary/40 rounded-full animate-bounce [animation-delay:-0.15s]" />
                  <div className="w-1.5 h-1.5 bg-primary/40 rounded-full animate-bounce" />
                </div>
              </div>
            </div>
          </div>
        )}

        {/* View Controls Helper */}
        <div className="absolute bottom-4 right-4 flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
          <Badge variant="secondary" className="bg-black/40 text-[9px] border-white/10 uppercase font-mono">
            R-Click: Rotate • Scroll: Zoom • L-Click: Details
          </Badge>
        </div>
      </Card>

      {/* Node Inspector Sidebar */}
      <AnimatePresence>
        {selectedNode && (
          <NodeInspector
            nodeId={selectedNode}
            onClose={() => setSelectedNode(null)}
          />
        )}
      </AnimatePresence>
    </div>
  )
}
