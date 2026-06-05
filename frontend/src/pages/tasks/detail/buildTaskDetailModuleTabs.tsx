import { RadarChartOutlined } from '@ant-design/icons';
import type { TabsProps } from 'antd';
import { Space, Tag } from 'antd';
import React from 'react';
import type { AuditSessionDetailDTO } from '@/types/auditSessionDetail';
import type { TaskCompletionStatusData } from '@/types/taskCompletionStatus';
import type { HumanApprovalPayload } from './planModel';
import QuickScanTab from './QuickScanTab';
import type { SeverityCounts } from './QuickScanTab';
import { TaskCompletionTodoPanel } from './TaskCompletionTodoPanel';
import { TaskEventsTimelineCard } from './TaskEventsTimelineCard';
import { TaskRuntimeLogsPanel } from './TaskRuntimeLogsPanel';

export type QuickScanData = {
  completed: boolean;
  findingsCount: number;
  reason: string;
  coverage: {
    coverage_rate: number;
    reviewed_files: number;
    total_files: number;
  };
  htmlReportAvailable: boolean;
  severityCounts?: SeverityCounts;
};

export type BuildTaskDetailModuleTabsParams = {
  detail: AuditSessionDetailDTO;
  sortedEvents: AuditSessionDetailDTO['events'];
  eventsTotal?: number;
  hasMoreOlder?: boolean;
  loadingOlderEvents?: boolean;
  onLoadOlderEvents?: () => Promise<void>;
  humanApprovalMetaMap: Record<string, HumanApprovalPayload>;
  onOpenEventDetail: (eventId: string) => void;
  onRequestFocusAuditChainNode: (neo4jElementId: string) => void;
  completionStatus: TaskCompletionStatusData | null;
  completionLoading: boolean;
  completionError: boolean;
  completionCompleted: number;
  completionTotal: number;
  onReloadCompletionStatus: () => void;
  quickScanData?: QuickScanData | null;
};

export function buildTaskDetailModuleTabs({
  detail,
  sortedEvents,
  eventsTotal,
  hasMoreOlder,
  loadingOlderEvents,
  onLoadOlderEvents,
  humanApprovalMetaMap,
  onOpenEventDetail,
  onRequestFocusAuditChainNode,
  completionStatus,
  completionLoading,
  completionError,
  completionCompleted,
  completionTotal,
  onReloadCompletionStatus,
  quickScanData,
}: BuildTaskDetailModuleTabsParams): NonNullable<TabsProps['items']> {
  const todoTagColor =
    completionTotal > 0 && completionCompleted === completionTotal
      ? 'success'
      : completionCompleted > 0
        ? 'processing'
        : 'default';

  const taskCompleted = detail.session.status === 'completed';

  const quickScanTagColor = quickScanData?.completed
    ? 'success'
    : quickScanData
      ? 'default'
      : undefined;

  return [
    {
      key: 'events',
      label: (
        <Space size={6}>
          <span>事件</span>
          <Tag color="blue">
            {eventsTotal != null && eventsTotal > sortedEvents.length
              ? `${sortedEvents.length}/${eventsTotal}`
              : sortedEvents.length}
          </Tag>
        </Space>
      ),
      children: (
        <TaskEventsTimelineCard
          detail={detail}
          sortedEvents={sortedEvents}
          hasMoreOlder={hasMoreOlder}
          loading={loadingOlderEvents}
          onLoadOlder={onLoadOlderEvents}
          humanApprovalMetaMap={humanApprovalMetaMap}
          onOpenEventDetail={onOpenEventDetail}
          onRequestFocusAuditChainNode={onRequestFocusAuditChainNode}
        />
      ),
    },
    {
      key: 'quick_scan',
      label: (
        <Space size={6}>
          <RadarChartOutlined style={{ fontSize: 14 }} />
          <span>扫描概览</span>
          {quickScanData?.completed && quickScanData.findingsCount > 0 ? (
            <Tag color={quickScanTagColor}>{quickScanData.findingsCount}</Tag>
          ) : null}
        </Space>
      ),
      children: (
        <QuickScanTab
          completed={quickScanData?.completed ?? false}
          findingsCount={quickScanData?.findingsCount ?? 0}
          reason={quickScanData?.reason ?? ''}
          coverage={quickScanData?.coverage ?? { coverage_rate: 0, reviewed_files: 0, total_files: 0 }}
          htmlReportAvailable={quickScanData?.htmlReportAvailable ?? false}
          taskCompleted={taskCompleted}
          severityCounts={quickScanData?.severityCounts}
        />
      ),
    },
    {
      key: 'todo',
      label: (
        <Space size={6}>
          <span>TODO</span>
          {completionTotal > 0 ? (
            <Tag color={todoTagColor}>
              {completionCompleted}/{completionTotal}
            </Tag>
          ) : null}
        </Space>
      ),
      children: (
        <TaskCompletionTodoPanel
          data={completionStatus}
          loading={completionLoading}
          error={completionError}
          completedCount={completionCompleted}
          totalCount={completionTotal}
          onReload={onReloadCompletionStatus}
        />
      ),
    },
    {
      key: 'logs',
      label: <span>运行日志</span>,
      children: <TaskRuntimeLogsPanel logs={detail.logs} />,
    },
  ];
}
