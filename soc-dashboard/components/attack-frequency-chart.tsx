'use client'

import React, { useState, useEffect, useMemo } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ChartConfig, ChartContainer, ChartTooltip } from '@/components/ui/area-charts-2'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { TrendingDown, TrendingUp, Loader2 } from 'lucide-react'
import { Area, AreaChart, CartesianGrid, XAxis, YAxis } from 'recharts'
import { cn } from '@/lib/utils'

// Color maps matching the existing dashboard palette
const SEVERITY_COLORS: Record<string, string> = {
    Critical: '#ef4444',
    High: '#f97316',
    Medium: '#eab308',
    Low: '#22c55e',
    Unknown: '#6b7280',
}

const TYPE_COLORS: Record<string, string> = {
    ip: '#06b6d4',
    domain: '#f59e0b',
    url: '#8b5cf6',
    sha256: '#10b981',
    sha1: '#ec4899',
    md5: '#f43f5e',
    email: '#6366f1',
    cve: '#f97316',
    ipv6: '#14b8a6',
    file_path: '#a855f7',
    registry_key: '#d946ef',
    unknown: '#6b7280',
}

const PERIODS = {
    '1d': { key: '1d', label: '1 Day' },
    '7d': { key: '7d', label: '7 Days' },
    '30d': { key: '30d', label: '30 Days' },
    '90d': { key: '90d', label: '90 Days' },
} as const

type PeriodKey = keyof typeof PERIODS
type GroupBy = 'severity' | 'type'

interface FrequencyData {
    group_by: string
    keys: string[]
    data: Array<Record<string, string | number>>
}

// Custom Tooltip Component
interface TooltipProps {
    active?: boolean
    payload?: Array<{
        dataKey: string
        value: number
        color: string
    }>
    label?: string
    stageMetrics: Array<{
        key: string
        label: string
        color: string
    }>
}

const CustomTooltip = ({ active, payload, label, stageMetrics }: TooltipProps) => {
    if (active && payload && payload.length) {
        return (
            <div className="rounded-lg border border-border/50 bg-popover/95 backdrop-blur-sm p-4 shadow-lg min-w-[200px]">
                <div className="text-sm font-semibold text-popover-foreground mb-3.5 pb-2 border-b border-border/50">
                    {label}
                </div>
                <div className="space-y-1.5">
                    {stageMetrics.map((stage) => {
                        const dataPoint = payload.find((p) => p.dataKey === stage.key)
                        const value = dataPoint?.value || 0

                        return (
                            <div key={stage.key} className="flex items-center justify-between gap-1.5">
                                <div className="flex items-center gap-2">
                                    <div className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: stage.color }} />
                                    <span className="text-xs font-medium text-muted-foreground">{stage.label}</span>
                                </div>
                                <span className="text-sm font-semibold text-popover-foreground">{value.toLocaleString()}</span>
                            </div>
                        )
                    })}
                </div>
            </div>
        )
    }
    return null
}

export default function AttackFrequencyChart() {
    const [selectedPeriod, setSelectedPeriod] = useState<PeriodKey>('30d')
    const [groupBy, setGroupBy] = useState<GroupBy>('severity')
    const [frequencyData, setFrequencyData] = useState<FrequencyData | null>(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)

    useEffect(() => {
        const fetchData = async () => {
            setLoading(true)
            setError(null)
            try {
                const res = await fetch(
                    `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/iocs/frequency?period=${selectedPeriod}&group_by=${groupBy}`
                )
                if (!res.ok) throw new Error(`API returned ${res.status}`)
                const data = await res.json()
                setFrequencyData(data)
            } catch (err) {
                console.error('Failed to fetch frequency data:', err)
                setError('Failed to load attack frequency data')
            } finally {
                setLoading(false)
            }
        }
        fetchData()
    }, [selectedPeriod, groupBy])

    // Build chart config and metrics from response data
    const { chartConfig, stageMetrics } = useMemo(() => {
        if (!frequencyData) return { chartConfig: {} as ChartConfig, stageMetrics: [] }

        const colorMap = groupBy === 'severity' ? SEVERITY_COLORS : TYPE_COLORS

        const config: ChartConfig = {}
        const metrics: Array<{ key: string; label: string; color: string }> = []

        for (const key of frequencyData.keys) {
            const color = colorMap[key] || colorMap[key.toLowerCase()] || '#6b7280'
            const label = groupBy === 'type' ? key.toUpperCase() : key
            config[key] = { label, color }
            metrics.push({ key, label, color })
        }

        return { chartConfig: config, stageMetrics: metrics }
    }, [frequencyData, groupBy])

    const currentData = frequencyData?.data || []

    // Calculate totals for the latest period
    const latestData = currentData.length > 0 ? currentData[currentData.length - 1] : null

    // Calculate % change between last two data points
    const getChangeForMetric = (metricKey: string): number => {
        if (currentData.length < 2) return 0
        const current = Number(currentData[currentData.length - 1]?.[metricKey]) || 0
        const previous = Number(currentData[currentData.length - 2]?.[metricKey]) || 0
        if (previous === 0) return current > 0 ? 100 : 0
        return Math.round(((current - previous) / previous) * 100)
    }

    return (
        <Card className="border-border/50 bg-card/50 backdrop-blur-sm border-border/30">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2 px-6 pt-6">
                <CardTitle className="text-lg font-semibold">Attack Frequency</CardTitle>
                <div className="flex items-center gap-2">
                    {/* Group By Selector */}
                    <Select value={groupBy} onValueChange={(v) => setGroupBy(v as GroupBy)}>
                        <SelectTrigger className="w-[130px] h-8 text-xs bg-transparent border-border/50">
                            <SelectValue />
                        </SelectTrigger>
                        <SelectContent align="end">
                            <SelectItem value="severity">By Severity</SelectItem>
                            <SelectItem value="type">By Type</SelectItem>
                        </SelectContent>
                    </Select>

                    {/* Period Selector */}
                    <Select value={selectedPeriod} onValueChange={(v) => setSelectedPeriod(v as PeriodKey)}>
                        <SelectTrigger className="w-[110px] h-8 text-xs bg-transparent border-border/50">
                            <SelectValue />
                        </SelectTrigger>
                        <SelectContent align="end">
                            {Object.values(PERIODS).map((period) => (
                                <SelectItem key={period.key} value={period.key}>
                                    {period.label}
                                </SelectItem>
                            ))}
                        </SelectContent>
                    </Select>
                </div>
            </CardHeader>

            <CardContent className="px-2.5 pb-6">
                {loading ? (
                    <div className="flex items-center justify-center h-[400px]">
                        <Loader2 className="h-8 w-8 animate-spin text-primary" />
                    </div>
                ) : error ? (
                    <div className="flex items-center justify-center h-[400px] text-muted-foreground text-sm">
                        {error}
                    </div>
                ) : (
                    <>
                        {/* Stats Section */}
                        <div className="px-2.5">
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
                                {stageMetrics.slice(0, 4).map((stage) => {
                                    const value = currentData.reduce((sum, item) => sum + (Number(item[stage.key]) || 0), 0)
                                    const change = getChangeForMetric(stage.key)

                                    return (
                                        <div key={stage.key} className="space-y-1">
                                            <div className="flex items-center gap-2.5">
                                                <div
                                                    className="w-0.5 h-12 rounded-full"
                                                    style={{ backgroundColor: stage.color }}
                                                />
                                                <div className="flex flex-col gap-2">
                                                    <div className="text-sm font-medium text-muted-foreground">{stage.label}</div>
                                                    <div className="flex items-center gap-2.5">
                                                        <span className="text-2xl font-semibold leading-none">{value.toLocaleString()}</span>
                                                        <span
                                                            className={cn(
                                                                'inline-flex items-center gap-1 text-xs font-medium',
                                                                change >= 0 ? 'text-green-500' : 'text-red-500',
                                                            )}
                                                        >
                                                            {change >= 0 ? <TrendingUp className="w-4 h-4" /> : <TrendingDown className="w-4 h-4" />}
                                                            {Math.abs(change)}%
                                                        </span>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    )
                                })}
                            </div>
                        </div>

                        {/* Chart */}
                        <ChartContainer
                            config={chartConfig}
                            className="h-[400px] w-full [&_.recharts-curve.recharts-tooltip-cursor]:stroke-current"
                        >
                            <AreaChart
                                accessibilityLayer
                                data={currentData}
                                margin={{ top: 10, bottom: 10, left: 20, right: 20 }}
                            >
                                <defs>
                                    {stageMetrics.map((stage) => (
                                        <linearGradient key={`fill-${stage.key}`} id={`fill-${stage.key}`} x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor={stage.color} stopOpacity={0.8} />
                                            <stop offset="95%" stopColor={stage.color} stopOpacity={0.1} />
                                        </linearGradient>
                                    ))}
                                </defs>

                                <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="hsl(var(--border))" strokeOpacity={0.5} />

                                <XAxis
                                    dataKey="period"
                                    tickLine={false}
                                    axisLine={false}
                                    tickMargin={10}
                                    tick={{ textAnchor: 'middle', fontSize: 12 }}
                                    interval="preserveStartEnd"
                                />

                                <YAxis hide />

                                <ChartTooltip
                                    cursor={{
                                        strokeDasharray: '4 4',
                                        stroke: 'hsl(var(--primary))',
                                        strokeWidth: 1,
                                        strokeOpacity: 0.6,
                                    }}
                                    content={<CustomTooltip stageMetrics={stageMetrics} />}
                                    offset={20}
                                />

                                {/* Stacked Areas - render in reverse order so first keys appear on top */}
                                {[...stageMetrics].reverse().map((stage, idx) => (
                                    <Area
                                        key={stage.key}
                                        dataKey={stage.key}
                                        type="monotone"
                                        fill={`url(#fill-${stage.key})`}
                                        fillOpacity={0.5 - idx * 0.05}
                                        stroke={stage.color}
                                        strokeWidth={2}
                                        stackId="a"
                                        dot={false}
                                        activeDot={{
                                            r: 4,
                                            fill: stage.color,
                                            stroke: 'hsl(var(--background))',
                                            strokeWidth: 1.5,
                                        }}
                                    />
                                ))}
                            </AreaChart>
                        </ChartContainer>
                    </>
                )}
            </CardContent>
        </Card>
    )
}
