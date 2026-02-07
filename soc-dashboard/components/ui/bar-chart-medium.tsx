'use client';

import React from 'react';
import { motion } from 'framer-motion';
import CountUp from 'react-countup';
import {
    BarChart,
    LinearXAxis,
    LinearXAxisTickSeries,
    LinearXAxisTickLabel,
    LinearYAxis,
    LinearYAxisTickSeries,
    BarSeries,
    Bar,
    GridlineSeries,
    Gridline,
    ChartTooltip,
} from 'reaviz';

export interface BarChartDataItem {
    key: string;
    data: number;
}

export interface BarChartMediumProps {
    data: BarChartDataItem[];
    title?: string;
    height?: number;
    showTimePeriod?: boolean;
    colorScheme?: string[];
    className?: string;
}

const DEFAULT_COLOR_SCHEME = [
    '#ef4444', // Critical - red
    '#f59e0b', // High - orange/amber
    '#22c55e', // Medium - green
    '#3b82f6', // Low - blue
    '#8b5cf6', // purple
];

export default function BarChartMedium({
    data,
    title = 'Incident Report',
    height = 280,
    showTimePeriod = false,
    colorScheme = DEFAULT_COLOR_SCHEME,
    className = '',
}: BarChartMediumProps) {
    // Guard against empty/undefined data
    if (!data || data.length === 0) {
        return (
            <div className={`flex flex-col pt-4 pb-4 bg-card rounded-xl border border-border/50 shadow-xl w-full overflow-hidden ${className}`}>
                <h3 className="text-xl px-6 pb-4 font-bold text-foreground">{title}</h3>
                <div className="flex items-center justify-center text-muted-foreground" style={{ height }}>
                    No data available
                </div>
            </div>
        );
    }

    const totalValue = data.reduce((sum, item) => sum + item.data, 0);

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className={`flex flex-col pt-4 pb-4 bg-card rounded-xl border border-border/50 shadow-xl w-full overflow-visible ${className}`}
        >
            <div className="flex justify-between items-center px-6 pb-4">
                <h3 className="text-xl font-bold text-foreground">{title}</h3>
            </div>

            <div className="px-4" style={{ height, overflow: 'visible' }}>
                <BarChart
                    height={height}
                    data={data}
                    xAxis={
                        <LinearXAxis
                            type="category"
                            tickSeries={
                                <LinearXAxisTickSeries
                                    label={
                                        <LinearXAxisTickLabel
                                            rotation={-45}
                                            fill="hsl(var(--muted-foreground))"
                                            fontSize={12}
                                        />
                                    }
                                />
                            }
                        />
                    }
                    yAxis={
                        <LinearYAxis
                            type="value"
                            tickSeries={<LinearYAxisTickSeries />}
                        />
                    }
                    series={
                        <BarSeries
                            colorScheme={colorScheme}
                            bar={
                                <Bar
                                    rx={4}
                                    ry={4}
                                    tooltip={
                                        <ChartTooltip
                                            content={({ x, y }: { x: string; y: number }) => (
                                                <div className="bg-card/95 backdrop-blur-sm border border-border rounded-lg px-3 py-2 shadow-xl z-50">
                                                    <div className="font-medium text-foreground">{x}</div>
                                                    <div className="text-lg font-bold text-primary">{typeof y === 'number' ? y.toLocaleString() : y}</div>
                                                </div>
                                            )}
                                        />
                                    }
                                />
                            }
                        />
                    }
                    gridlines={
                        <GridlineSeries
                            line={<Gridline strokeColor="hsl(var(--border) / 0.5)" />}
                        />
                    }
                />
            </div>

            <div className="flex justify-around items-center mt-4 px-6 pt-4 border-t border-border/30">
                <div className="text-center">
                    <p className="text-xs text-muted-foreground uppercase tracking-wide">Total</p>
                    <p className="text-2xl font-bold text-foreground">
                        <CountUp end={totalValue} duration={2} separator="," />
                    </p>
                </div>
                <div className="text-center">
                    <p className="text-xs text-muted-foreground uppercase tracking-wide">Categories</p>
                    <p className="text-2xl font-bold text-foreground">{data.length}</p>
                </div>
                <div className="text-center">
                    <p className="text-xs text-muted-foreground uppercase tracking-wide">Avg</p>
                    <p className="text-2xl font-bold text-foreground">
                        <CountUp
                            end={Math.round(totalValue / (data.length || 1))}
                            duration={2}
                            separator=","
                        />
                    </p>
                </div>
            </div>
        </motion.div>
    );
}
