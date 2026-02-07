'use client';

import React from 'react';
import { motion } from 'framer-motion';
import {
    BarChart,
    LinearXAxis,
    LinearYAxis,
    LinearYAxisTickSeries,
    LinearYAxisTickLabel,
    BarSeries,
    Bar,
    GridlineSeries,
    Gridline,
    ChartTooltip,
} from 'reaviz';

export interface HorizontalBarDataItem {
    key: string;
    data: number;
}

export interface HorizontalBarMediumProps {
    data: HorizontalBarDataItem[];
    title?: string;
    height?: number;
    colorScheme?: string[];
    className?: string;
}

const DEFAULT_COLOR_SCHEME = ['#8b5cf6', '#06b6d4', '#22c55e', '#f59e0b', '#ec4899'];

export default function HorizontalBarMedium({
    data,
    title = 'Category Report',
    height = 300,
    colorScheme = DEFAULT_COLOR_SCHEME,
    className = '',
}: HorizontalBarMediumProps) {
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

    // Get top 3 for summary
    const sortedData = [...data].sort((a, b) => b.data - a.data);
    const top3 = sortedData.slice(0, 3);

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className={`flex flex-col pt-4 pb-4 bg-card rounded-xl border border-border/50 shadow-xl w-full overflow-visible ${className}`}
        >
            <h3 className="text-xl px-6 pb-4 font-bold text-foreground">{title}</h3>

            <div className="flex-grow px-4" style={{ height, overflow: 'visible' }}>
                <BarChart
                    height={height}
                    data={data}
                    yAxis={
                        <LinearYAxis
                            type="category"
                            tickSeries={
                                <LinearYAxisTickSeries
                                    label={
                                        <LinearYAxisTickLabel
                                            fill="hsl(var(--muted-foreground))"
                                            fontSize={12}
                                        />
                                    }
                                />
                            }
                        />
                    }
                    xAxis={
                        <LinearXAxis type="value" axisLine={null} />
                    }
                    series={
                        <BarSeries
                            layout="horizontal"
                            colorScheme={colorScheme}
                            bar={
                                <Bar
                                    rx={4}
                                    ry={4}
                                    tooltip={
                                        <ChartTooltip
                                            content={({ x, y }: { x: number; y: string }) => (
                                                <div className="bg-card/95 backdrop-blur-sm border border-border rounded-lg px-3 py-2 shadow-xl z-50">
                                                    <div className="font-medium text-foreground">{y}</div>
                                                    <div className="text-lg font-bold text-primary">{typeof x === 'number' ? x.toLocaleString() : x}</div>
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
                {top3.map((item, index) => (
                    <div key={item.key} className="text-center">
                        <p className="text-xs text-muted-foreground uppercase tracking-wide truncate max-w-[100px]">
                            {item.key}
                        </p>
                        <p className="text-lg font-bold" style={{ color: colorScheme[index % colorScheme.length] }}>
                            {item.data.toLocaleString()}
                        </p>
                    </div>
                ))}
            </div>
        </motion.div>
    );
}
