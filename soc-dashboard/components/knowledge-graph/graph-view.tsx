"use client"

import { useState, useMemo, useEffect, useRef } from "react"
import dynamic from "next/dynamic"
import { motion, AnimatePresence } from "framer-motion"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Network, Search, RefreshCw, Layers, ZoomIn } from "lucide-react"
import { Input } from "@/components/ui/input"
import { Slider } from "@/components/ui/slider"
import { Switch } from "@/components/ui/switch"
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
  ip: "#0ea5e9",      // Vibrant Light Blue
  domain: "#f59e0b",  // Amber
  md5: "#ec4899",     // Pink (Match reference image 4/5)
  sha256: "#10b981",  // Emerald
  url: "#8b5cf6",     // Violet
  email: "#6366f1",   // Indigo
  cve: "#f43f5e",     // Rose
  context: "#94a3b8", // Slate (Articles)
  unknown: "#475569",
}

export default function KnowledgeGraphView() {
  const [data, setData] = useState<{ nodes: any[]; links: any[] }>({ nodes: [], links: [] })
  const [loading, setLoading] = useState(true)
  const [selectedNode, setSelectedNode] = useState<string | null>(null)
  const [searchTerm, setSearchTerm] = useState("")
  const [minConfidence, setMinConfidence] = useState(0.3)
  const [minDegree, setMinDegree] = useState(0)
  const [isPhysicsFrozen, setIsPhysicsFrozen] = useState(false)
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
      
      const safeNodes = Array.isArray(graphData.nodes) ? graphData.nodes : []
      const safeEdges = Array.isArray(graphData.edges) ? graphData.edges : []

      const formatted = {
        nodes: safeNodes.map((n: any) => {
          const type = n?.data?.type || "unknown"
          const isHub = type === "context"
          return {
            id: n?.data?.id || `unknown-${Math.random()}`,
            name: isHub ? "Article" : (n?.data?.id || "Unknown"),
            label: isHub ? "FEED ENTRY" : (n?.data?.id || "Unknown"),
            type: type,
            confidence: n?.data?.confidence || 0.5,
            color: TYPE_COLORS[type] || TYPE_COLORS.unknown,
            degree: 0 // Will be computed
          }
        }),
        links: safeEdges.map((e: any) => ({
          source: e?.data?.source,
          target: e?.data?.target,
          type: e?.data?.type || "RELATED",
          weight: e?.data?.weight || 1,
        })).filter((l: any) => l.source && l.target),
      }

      // Compute degree client-side for sizing
      const degreeMap: Record<string, number> = {}
      formatted.links.forEach((l: any) => {
        degreeMap[l.source] = (degreeMap[l.source] || 0) + 1
        degreeMap[l.target] = (degreeMap[l.target] || 0) + 1
      })
        formatted.nodes.forEach((n: any) => {
          n.degree = degreeMap[n.id] || 0
          // Significantly smaller radius as requested
          n.val = n.type === 'context' ? 6 : Math.sqrt(n.degree + 1) * 1.5 * (n.confidence || 0.5) + 2
        })

      setData(formatted)
    } catch (error) {
      console.error("Failed to fetch graph:", error)
    } finally {
      setLoading(false)
    }
  }

  const filteredData = useMemo(() => {
    const term = searchTerm.toLowerCase()
    const safeNodes = Array.isArray(data?.nodes) ? data.nodes : []
    const safeLinks = Array.isArray(data?.links) ? data.links : []
    
    const filteredNodes = safeNodes.filter((n) => {
      if (term && n.id && !n.id.toLowerCase().includes(term)) return false;
      if (n.degree < minDegree && n.type !== 'context') return false;
      return true;
    })

    const nodeIds = new Set(filteredNodes.map(n => n.id))
    const filteredLinks = safeLinks.filter(l => 
      nodeIds.has(typeof l.source === 'object' ? l.source?.id : l.source) && 
      nodeIds.has(typeof l.target === 'object' ? l.target?.id : l.target)
    )

    return {
      nodes: filteredNodes,
      links: filteredLinks, 
    }
  }, [data, searchTerm])

  const handleNodeClick = (node: any) => {
    setSelectedNode(node.id)
    if (graphRef.current) {
      // Zoom to at least level 4, but don't zoom out if already closer
      const currentZoom = graphRef.current.zoom()
      graphRef.current.centerAt(node.x, node.y, 1000)
      graphRef.current.zoom(Math.max(4, currentZoom), 1000)
    }
  }

  useEffect(() => {
    if (graphRef.current && !isPhysicsFrozen) {
      graphRef.current.d3ReheatSimulation();
    }
  }, [isPhysicsFrozen])

  // Configure forces for balanced, interactive clustering
  useEffect(() => {
    if (graphRef.current) {
      const fg = graphRef.current;
      const d3 = (window as any).d3;
      // Guard: Ensure D3 is loaded and force simulation is initialized
      if (!d3 || !fg.d3Force('link')) return;

      // Stronger repulsion to spread out large clusters
      fg.d3Force('charge', d3.forceManyBody().strength(-120));
      // Increased link distance to give more breathing room
      fg.d3Force('link').distance(80);
      // Centering to keep it in frame
      fg.d3Force('center', d3.forceCenter());
      fg.d3Force('x', d3.forceX().strength(0.05));
      fg.d3Force('y', d3.forceY().strength(0.05));
      // Collision force proportional to node size
      fg.d3Force('collide', d3.forceCollide((node: any) => node.val + 5));
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
              <Slider
                value={[minConfidence]}
                min={0}
                max={1}
                step={0.05}
                onValueChange={(vals) => setMinConfidence(vals[0])}
                className="py-2"
              />
            </div>

            <div className="space-y-3 p-2 bg-white/5 rounded-lg border border-white/5">
              <div className="flex items-center justify-between text-[10px] text-muted-foreground uppercase font-black tracking-widest">
                <span>Min Connections</span>
                <span className="text-primary">{minDegree}</span>
              </div>
              <Slider
                value={[minDegree]}
                min={0}
                max={10}
                step={1}
                onValueChange={(vals) => setMinDegree(vals[0])}
                className="py-2"
              />
            </div>

            <div className="flex items-center justify-between p-2 bg-white/5 rounded-lg border border-white/5 text-[10px] text-muted-foreground uppercase font-black tracking-widest">
              <span>Freeze Physics</span>
              <Switch 
                checked={isPhysicsFrozen}
                onCheckedChange={setIsPhysicsFrozen}
              />
            </div>
          </div>
        </Card>

        {/* Legend */}
        <Card className="p-4 bg-background/40 backdrop-blur-2xl border-white/10 text-[10px] font-mono tracking-tighter">
          <div className="grid grid-cols-2 gap-y-2 gap-x-4">
            {Object.entries(TYPE_COLORS)
              .filter(([type]) => data.nodes.some(n => n.type === type))
              .map(([type, color]) => (
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
          nodeLabel={(node: any) => node.type === 'context' ? `Article Hub\nConnections: ${node.degree}` : `${node.id}\nConfidence: ${(node.confidence * 100).toFixed(1)}%`}
          nodeColor="color"
          nodeRelSize={1}
          linkWidth={1.5}
          linkColor={(link: any) => {
            const type = link.type || "RELATED"
            const colors: Record<string, string> = {
              'MENTIONED_IN': 'rgba(14,165,233,0.3)',
              'CO_OCCURS_WITH': 'rgba(16,185,129,0.3)',
              'RELATED': 'rgba(251,146,60,0.6)'
            }
            return colors[type] || 'rgba(255,255,255,0.08)'
          }}
          linkDirectionalArrowLength={4}
          linkDirectionalArrowRelPos={1}
          onNodeClick={handleNodeClick}
          enableNodeDrag={true}
          warmupTicks={300}
          cooldownTicks={0} // Settle immediately after warmup; dragging reheats automatically
          nodeCanvasObject={(node: any, ctx: CanvasRenderingContext2D, globalScale) => {
            const size = node.val || 5;
            const isHub = node.type === 'context';
            
            // Halo/Glow effect for clusters
            if (isHub) {
              const gradient = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, size * 2);
              gradient.addColorStop(0, `${node.color}33`);
              gradient.addColorStop(1, 'transparent');
              ctx.fillStyle = gradient;
              ctx.beginPath();
              ctx.arc(node.x, node.y, size * 2, 0, 2 * Math.PI);
              ctx.fill();
            }

            // Draw Geometric Shape (Polygons)
            const sides = isHub ? 8 : (node.type === 'cve' ? 6 : (node.type === 'domain' ? 5 : 4));
            ctx.beginPath();
            for (let i = 0; i < sides; i++) {
                const angle = (i * 2 * Math.PI / sides) - Math.PI / 2;
                const tx = node.x + size * Math.cos(angle);
                const ty = node.y + size * Math.sin(angle);
                i === 0 ? ctx.moveTo(tx, ty) : ctx.lineTo(tx, ty);
            }
            ctx.closePath();
            ctx.fillStyle = node.color;
            ctx.fill();
            
            // Border
            ctx.strokeStyle = isHub ? '#fff' : 'rgba(255,255,255,0.2)';
            ctx.lineWidth = 1 / globalScale;
            ctx.stroke();

            // Label Rendering - Gated strictly by zoom level
            if (globalScale > 2.5) {
              const rawLabel = isHub ? "ARTICLE HUB" : node.id;
              const label = rawLabel.length > 15 ? rawLabel.substring(0, 13) + '…' : rawLabel;
              const fontSize = isHub ? 14 / globalScale : 11 / globalScale;
              ctx.font = `${isHub ? 'bold' : 'normal'} ${fontSize}px Sans-Serif`;
              ctx.textAlign = 'center';
              ctx.textBaseline = 'middle';
              
              const tw = ctx.measureText(label).width;
              ctx.fillStyle = 'rgba(0,0,0,0.85)';
              ctx.fillRect(node.x - tw/2 - 2, node.y + size + 2, tw + 4, fontSize + 3);
              
              ctx.fillStyle = isHub ? '#38bdf8' : '#fff';
              ctx.fillText(label, node.x, node.y + size + 2 + fontSize/2);
            }
          }}
          linkCanvasObject={(link: any, ctx: CanvasRenderingContext2D, globalScale) => {
            if (globalScale < 5) return; // Only show on very close zoom
            const start = link.source;
            const end = link.target;
            if (typeof start !== 'object' || typeof end !== 'object') return;

            const mx = (start.x + end.x) / 2;
            const my = (start.y + end.y) / 2;
            const relType = link.type || "RELATES";
            
            ctx.font = `${8 / globalScale}px monospace`;
            ctx.fillStyle = 'rgba(255,255,255,0.5)';
            ctx.textAlign = 'center';
            ctx.fillText(relType, mx, my);
          }}
          linkCanvasObjectMode={() => "after"}
          nodeCanvasObjectMode={() => "replace"}
          d3AlphaDecay={isPhysicsFrozen ? 1 : 0.03}
          d3VelocityDecay={isPhysicsFrozen ? 1 : 0.4}
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
