"use client";

import { LabelList, Pie, PieChart, Cell, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { motion } from "framer-motion";
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { TrendingDown, TrendingUp } from "lucide-react";

export interface PieChartDataItem {
    name: string;
    value: number;
    fill: string;
}

export interface SizedPieChartProps {
    data: PieChartDataItem[];
    title?: string;
    description?: string;
    trend?: number;
    trendLabel?: string;
    className?: string;
}

const BASE_RADIUS = 40;
const SIZE_INCREMENT = 10;

// Custom tooltip component
const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
        const data = payload[0];
        return (
            <div className="bg-card/95 backdrop-blur-sm border border-border rounded-lg px-3 py-2 shadow-xl">
                <div className="flex items-center gap-2">
                    <div
                        className="w-3 h-3 rounded-sm"
                        style={{ backgroundColor: data.payload.fill }}
                    />
                    <span className="font-medium text-foreground">{data.name}</span>
                </div>
                <p className="text-lg font-bold text-foreground mt-1">
                    {data.value.toLocaleString()}
                </p>
            </div>
        );
    }
    return null;
};

// Custom legend
const CustomLegend = ({ payload }: any) => {
    return (
        <div className="flex flex-wrap justify-center gap-x-4 gap-y-1 mt-2 px-2">
            {payload?.map((entry: any, index: number) => (
                <div key={index} className="flex items-center gap-1.5">
                    <div
                        className="w-2.5 h-2.5 rounded-sm shrink-0"
                        style={{ backgroundColor: entry.color }}
                    />
                    <span className="text-xs text-muted-foreground">{entry.value}</span>
                </div>
            ))}
        </div>
    );
};

export default function SizedPieChart({
    data,
    title = "Sized Pie Chart",
    description = "Distribution Overview",
    trend,
    trendLabel = "",
    className = "",
}: SizedPieChartProps) {
    // Guard against empty data
    if (!data || data.length === 0) {
        return (
            <Card className={`flex flex-col bg-card border-border/50 ${className}`}>
                <CardHeader className="items-center pb-0">
                    <CardTitle>{title}</CardTitle>
                    <CardDescription>{description}</CardDescription>
                </CardHeader>
                <CardContent className="flex-1 flex items-center justify-center min-h-[300px]">
                    <p className="text-muted-foreground">No data available</p>
                </CardContent>
            </Card>
        );
    }

    // Sort data by value ascending so smaller slices are inner (for the extended effect)
    const sortedData = [...data].sort((a, b) => a.value - b.value);
    const total = sortedData.reduce((sum, d) => sum + d.value, 0);

    const TrendIcon = trend && trend >= 0 ? TrendingUp : TrendingDown;
    const trendColor = trend && trend >= 0 ? "text-green-500 bg-green-500/10" : "text-red-500 bg-red-500/10";

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
        >
            <Card className={`flex flex-col bg-card border-border/50 ${className}`}>
                <CardHeader className="items-center pb-0">
                    <CardTitle className="flex items-center gap-2">
                        {title}
                        {trend !== undefined && (
                            <Badge variant="outline" className={`border-none ${trendColor}`}>
                                <TrendIcon className="h-4 w-4 mr-1" />
                                <span>{Math.abs(trend)}%{trendLabel && ` ${trendLabel}`}</span>
                            </Badge>
                        )}
                    </CardTitle>
                    <CardDescription>{description}</CardDescription>
                </CardHeader>
                <CardContent className="flex-1 pb-4 pt-4">
                    <ResponsiveContainer width="100%" height={340}>
                        <PieChart>
                            <Tooltip content={<CustomTooltip />} />
                            {sortedData.map((entry, index) => {
                                const startAngle =
                                    (sortedData
                                        .slice(0, index)
                                        .reduce((sum, d) => sum + d.value, 0) /
                                        total) *
                                    360;
                                const endAngle =
                                    (sortedData
                                        .slice(0, index + 1)
                                        .reduce((sum, d) => sum + d.value, 0) /
                                        total) *
                                    360;

                                return (
                                    <Pie
                                        key={`pie-${index}`}
                                        data={[{ ...entry, name: entry.name }]}
                                        cx="50%"
                                        cy="45%"
                                        innerRadius={30}
                                        outerRadius={BASE_RADIUS + index * SIZE_INCREMENT}
                                        dataKey="value"
                                        nameKey="name"
                                        cornerRadius={4}
                                        startAngle={startAngle}
                                        endAngle={endAngle}
                                        stroke="none"
                                    >
                                        <Cell
                                            fill={entry.fill}
                                            className="cursor-pointer transition-opacity hover:opacity-80"
                                        />
                                    </Pie>
                                );
                            })}
                            <Legend
                                content={<CustomLegend />}
                                verticalAlign="bottom"
                            />
                        </PieChart>
                    </ResponsiveContainer>
                </CardContent>
            </Card>
        </motion.div>
    );
}
