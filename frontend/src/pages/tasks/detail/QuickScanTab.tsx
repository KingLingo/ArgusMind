import {
  CheckCircleFilled,
  CloseCircleFilled,
  InfoCircleFilled,
} from '@ant-design/icons';
import { Progress, Spin, Tag, Typography, theme } from 'antd';
import React from 'react';
import { TASK_EVENTS_SCROLL_CLASS, eventTimelineScrollArea } from './detailStyles';

export type SeverityCounts = {
  critical: number;
  high: number;
  medium: number;
  low: number;
};

export type QuickScanTabProps = {
  /** 快速扫描是否已完成 */
  completed: boolean;
  /** 快速扫描发现的潜在问题数量 */
  findingsCount: number;
  /** 扫描描述 */
  reason: string;
  /** 覆盖率数据 */
  coverage: {
    coverage_rate: number;
    reviewed_files: number;
    total_files: number;
  };
  /** HTML 报告是否可用 */
  htmlReportAvailable: boolean;
  /** 任务是否已完成 */
  taskCompleted: boolean;
  /** 下载 HTML 报告回调 */
  onDownloadReport?: () => void;
  /** 严重等级分布 */
  severityCounts?: SeverityCounts;
};

const SEVERITY_CONFIG = {
  critical: { color: '#dc2626', label: '严重' },
  high: { color: '#f97316', label: '高危' },
  medium: { color: '#eab308', label: '中危' },
  low: { color: '#3b82f6', label: '低危' },
} as const;

const QuickScanTab: React.FC<QuickScanTabProps> = ({
  completed,
  findingsCount,
  reason,
  coverage,
  htmlReportAvailable,
  taskCompleted,
  severityCounts,
}) => {
  const { token } = theme.useToken();

  const coverageRate = coverage?.coverage_rate ?? 0;
  const reviewedFiles = coverage?.reviewed_files ?? 0;
  const totalFiles = coverage?.total_files ?? 0;
  const coverageColor =
    coverageRate >= 80 ? '#22c55e' : coverageRate >= 50 ? '#f59e0b' : '#ef4444';

  const showSeverity = completed && severityCounts != null;
  const totalSeverity = showSeverity
    ? severityCounts.critical +
      severityCounts.high +
      severityCounts.medium +
      severityCounts.low
    : 0;

  return (
    <div
      className={TASK_EVENTS_SCROLL_CLASS}
      style={{
        ...eventTimelineScrollArea,
        height: '100%',
        overflowY: 'auto',
        padding: '8px 4px 16px',
      }}
    >
      {/* 快速扫描状态卡片 */}
      <div
        style={{
          borderRadius: 10,
          border: `1px solid ${token.colorBorderSecondary}`,
          background: token.colorBgContainer,
          padding: '16px 20px',
          marginBottom: 16,
        }}
      >
        <div
          style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}
        >
          {completed ? (
            <CheckCircleFilled style={{ color: '#22c55e', fontSize: 20 }} />
          ) : taskCompleted ? (
            <CloseCircleFilled style={{ color: '#ef4444', fontSize: 20 }} />
          ) : (
            <Spin size="small" />
          )}
          <Typography.Text strong style={{ fontSize: 15 }}>
            规则引擎快速扫描
          </Typography.Text>
          {completed ? (
            <Tag color="success" bordered={false} style={{ marginLeft: 'auto' }}>
              已完成
            </Tag>
          ) : taskCompleted ? (
            <Tag color="default" bordered={false} style={{ marginLeft: 'auto' }}>
              未执行
            </Tag>
          ) : (
            <Tag color="processing" bordered={false} style={{ marginLeft: 'auto' }}>
              等待中
            </Tag>
          )}
        </div>

        {completed ? (
          <div>
            <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
              <div>
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  发现潜在问题
                </Typography.Text>
                <div style={{ fontSize: 28, fontWeight: 700, lineHeight: 1.2 }}>
                  {findingsCount}
                </div>
              </div>
              <div style={{ flex: 1, minWidth: 120 }}>
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  扫描说明
                </Typography.Text>
                <div
                  style={{
                    fontSize: 13,
                    marginTop: 4,
                    color: token.colorTextSecondary,
                  }}
                >
                  {reason || '基于正则规则和组件漏洞库的预扫描'}
                </div>
              </div>
            </div>

            {/* 严重等级分布 */}
            {showSeverity && totalSeverity > 0 && (
              <div
                style={{
                  display: 'flex',
                  gap: 16,
                  marginTop: 14,
                  paddingTop: 12,
                  borderTop: `1px solid ${token.colorBorderSecondary}`,
                }}
              >
                <Typography.Text
                  type="secondary"
                  style={{ fontSize: 12, marginRight: 4 }}
                >
                  等级分布：
                </Typography.Text>
                {(
                  Object.entries(SEVERITY_CONFIG) as [
                    keyof typeof SEVERITY_CONFIG,
                    (typeof SEVERITY_CONFIG)[keyof typeof SEVERITY_CONFIG],
                  ][]
                ).map(([key, cfg]) => {
                  const count = severityCounts[key] ?? 0;
                  return (
                    <span
                      key={key}
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 5,
                        fontSize: 13,
                      }}
                    >
                      <span
                        style={{
                          width: 8,
                          height: 8,
                          borderRadius: '50%',
                          background: cfg.color,
                          flexShrink: 0,
                        }}
                      />
                      {cfg.label}
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        {count}
                      </Typography.Text>
                    </span>
                  );
                })}
              </div>
            )}
          </div>
        ) : (
          <Typography.Text type="secondary" style={{ fontSize: 13 }}>
            {taskCompleted
              ? '本次审计未执行快速扫描'
              : '快速扫描将在信息收集阶段自动执行'}
          </Typography.Text>
        )}
      </div>

      {/* 覆盖率卡片 */}
      <div
        style={{
          borderRadius: 10,
          border: `1px solid ${token.colorBorderSecondary}`,
          background: token.colorBgContainer,
          padding: '16px 20px',
          marginBottom: 16,
        }}
      >
        <div
          style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}
        >
          <InfoCircleFilled style={{ color: '#1677ff', fontSize: 18 }} />
          <Typography.Text strong style={{ fontSize: 15 }}>
            审计覆盖率
          </Typography.Text>
        </div>

        {totalFiles > 0 ? (
          <>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 16,
                marginBottom: 8,
              }}
            >
              <Progress
                type="circle"
                percent={Math.round(coverageRate)}
                size={64}
                strokeColor={coverageColor}
                format={(pct) => (
                  <span style={{ fontSize: 16, fontWeight: 600 }}>{pct}%</span>
                )}
              />
              <div>
                <div style={{ fontSize: 13 }}>
                  <Typography.Text type="secondary">已审查文件</Typography.Text>
                  <span style={{ fontWeight: 600, marginLeft: 6 }}>
                    {reviewedFiles} / {totalFiles}
                  </span>
                </div>
                <div
                  style={{
                    fontSize: 12,
                    color: token.colorTextTertiary,
                    marginTop: 4,
                  }}
                >
                  {totalFiles - reviewedFiles > 0
                    ? `还有 ${totalFiles - reviewedFiles} 个文件未审查`
                    : '所有文件均已覆盖'}
                </div>
              </div>
            </div>
          </>
        ) : taskCompleted ? (
          <Typography.Text type="secondary" style={{ fontSize: 13 }}>
            覆盖率数据不可用
          </Typography.Text>
        ) : (
          <Typography.Text type="secondary" style={{ fontSize: 13 }}>
            覆盖率将在审计过程中实时更新
          </Typography.Text>
        )}
      </div>

      {/* HTML 报告下载 */}
      {taskCompleted && (
        <div
          style={{
            borderRadius: 10,
            border: `1px solid ${token.colorBorderSecondary}`,
            background: token.colorBgContainer,
            padding: '16px 20px',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <Typography.Text strong style={{ fontSize: 14 }}>
                审计报告
              </Typography.Text>
              <div
                style={{
                  fontSize: 12,
                  color: token.colorTextTertiary,
                  marginTop: 2,
                }}
              >
                {htmlReportAvailable
                  ? 'HTML 格式完整报告已生成，包含评分、漏洞详情和覆盖率'
                  : '报告尚未生成'}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default QuickScanTab;
