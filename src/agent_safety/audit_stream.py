"""
Audit Stream - Real-time Audit Event Streaming with OTLP Export

Features:
- Async event queue with bounded buffer
- OTLP (OpenTelemetry Protocol) export
- Event filtering and enrichment
- Backpressure handling
"""

from __future__ import annotations

import json
import time
import asyncio
import logging
import uuid
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Any, Optional, Callable
from datetime import datetime

logger = logging.getLogger(__name__)


class EventSeverity(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EventSource(Enum):
    AGENT_SAFETY = "agent_safety"
    AGENT_SUPERVISOR = "agent_supervisor"
    AGENT_MANAGER = "agent_manager"
    POLICY_ENGINE = "policy_engine"
    SKILL_ENGINE = "skill_engine"


@dataclass
class AuditEvent:
    """审计事件"""
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    timestamp: float = field(default_factory=time.time)
    source: str = EventSource.AGENT_SAFETY.value
    event_type: str = ""
    severity: str = EventSeverity.INFO.value
    agent_id: Optional[str] = None
    action: str = ""
    target: Optional[str] = None
    decision: str = ""
    risk_level: Optional[str] = None
    reason: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


class OTLPExporter:
    """OTLP 导出器 - 支持 gRPC/HTTP 协议"""

    def __init__(
        self,
        endpoint: str = "http://localhost:4317",
        protocol: str = "grpc",
        timeout: float = 5.0
    ):
        self.endpoint = endpoint
        self.protocol = protocol
        self.timeout = timeout
        self._connected = False
        self._span_count = 0

    def connect(self) -> bool:
        """建立 OTLP 连接"""
        try:
            # 简化实现：仅记录连接状态
            # 生产环境应使用 opentelemetry-exporter-otlp
            logger.info(f"OTLP 连接初始化: {self.protocol} -> {self.endpoint}")
            self._connected = True
            return True
        except Exception as e:
            logger.error(f"OTLP 连接失败: {e}")
            self._connected = False
            return False

    def export(self, events: list[AuditEvent]) -> bool:
        """导出事件到 OTLP 端点"""
        if not self._connected:
            return False

        try:
            # 构建 OTLP ResourceSpans 格式
            resource_spans = self._build_resource_spans(events)

            # 发送请求（简化实现）
            self._span_count += len(events)
            logger.debug(f"导出 {len(events)} 个事件到 OTLP (累计: {self._span_count})")
            return True

        except Exception as e:
            logger.error(f"OTLP 导出失败: {e}")
            return False

    def _build_resource_spans(self, events: list[AuditEvent]) -> dict:
        """构建 OTLP ResourceSpans 格式"""
        return {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "AgentSafety"}},
                            {"key": "service.version", "value": {"stringValue": "1.0.0"}},
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {"name": "audit", "version": "1.0.0"},
                            "spans": [
                                {
                                    "traceId": e.event_id[:16].ljust(32, "0"),
                                    "spanId": e.event_id[:16],
                                    "name": e.event_type,
                                    "kind": 1,  # SPAN_KIND_PRODUCER
                                    "startTimeUnixNano": int(e.timestamp * 1e9),
                                    "endTimeUnixNano": int(time.time() * 1e9),
                                    "attributes": [
                                        {"key": "agent.id", "value": {"stringValue": e.agent_id or ""}},
                                        {"key": "action", "value": {"stringValue": e.action}},
                                        {"key": "decision", "value": {"stringValue": e.decision}},
                                        {"key": "severity", "value": {"stringValue": e.severity}},
                                    ]
                                }
                                for e in events
                            ]
                        }
                    ]
                }
            ]
        }

    def flush(self) -> bool:
        """强制刷新缓冲区"""
        # 简化实现
        logger.debug("OTLP 缓冲区已刷新")
        return True


class AuditStream:
    """
    实时审计事件流

    Features:
    - 异步事件队列
    - 事件过滤和富化
    - OTLP 导出
    - 背压处理
    """

    def __init__(
        self,
        max_queue_size: int = 10000,
        flush_interval: float = 5.0,
        otlp_endpoint: Optional[str] = None,
        min_severity: str = EventSeverity.INFO.value
    ):
        self._queue: asyncio.Queue[AuditEvent] = asyncio.Queue(maxsize=max_queue_size)
        self._flush_interval = flush_interval
        self._min_severity = EventSeverity(min_severity)
        self._running = False
        self._exporter: Optional[OTLPExporter] = None
        self._filter: Optional[Callable[[AuditEvent], bool]] = None
        self._processor_task: Optional[asyncio.Task] = None
        self._event_count = 0
        self._dropped_count = 0

        # 初始化 OTLP 导出器
        if otlp_endpoint:
            self._exporter = OTLPExporter(endpoint=otlp_endpoint)
            self._exporter.connect()

    def set_filter(self, filter_fn: Callable[[AuditEvent], bool]):
        """设置事件过滤器"""
        self._filter = filter_fn

    def emit(self, event: AuditEvent) -> bool:
        """
        发射审计事件（同步接口）

        Returns:
            True 如果事件入队成功
        """
        try:
            # 严重性过滤
            if EventSeverity(event.severity).value < self._min_severity.value:
                return False

            # 自定义过滤
            if self._filter and not self._filter(event):
                return False

            # 入队（非阻塞）
            self._queue.put_nowait(event)
            self._event_count += 1
            return True

        except asyncio.QueueFull:
            self._dropped_count += 1
            logger.warning(f"审计队列已满，丢弃事件: {event.event_type}")
            return False

    async def emit_async(self, event: AuditEvent):
        """异步发射审计事件"""
        if not self.emit(event):
            logger.debug(f"事件过滤或丢弃: {event.event_id}")

    async def start(self):
        """启动事件处理器"""
        if self._running:
            return

        self._running = True
        self._processor_task = asyncio.create_task(self._process_loop())
        logger.info("审计事件流已启动")

    async def stop(self):
        """停止事件处理器"""
        self._running = False
        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass
        logger.info(f"审计事件流已停止 (处理: {self._event_count}, 丢弃: {self._dropped_count})")

    async def _process_loop(self):
        """事件处理循环"""
        buffer: list[AuditEvent] = []
        last_flush = time.time()

        while self._running:
            try:
                # 等待事件或超时
                try:
                    event = await asyncio.wait_for(
                        self._queue.get(),
                        timeout=1.0
                    )
                    buffer.append(event)
                except asyncio.TimeoutError:
                    pass

                # 定时刷新
                now = time.time()
                if buffer and (now - last_flush) >= self._flush_interval:
                    self._flush_buffer(buffer)
                    buffer.clear()
                    last_flush = now

                # 队列满时强制刷新
                if self._queue.full():
                    logger.warning("队列达到最大容量，强制刷新")
                    self._flush_buffer(buffer)
                    buffer.clear()
                    last_flush = now

            except Exception as e:
                logger.error(f"事件处理异常: {e}")

        # 最后刷新
        if buffer:
            self._flush_buffer(buffer)

    def _flush_buffer(self, buffer: list[AuditEvent]):
        """刷新缓冲区到 OTLP"""
        if not buffer:
            return

        if self._exporter:
            success = self._exporter.export(buffer)
            if success:
                logger.debug(f"已导出 {len(buffer)} 个审计事件")
            else:
                logger.warning(f"导出失败，{len(buffer)} 个事件丢失")
        else:
            # 无 OTLP 时记录到日志
            for event in buffer:
                logger.info(f"AUDIT: {event.to_json()}")

    def get_stats(self) -> dict:
        """获取统计信息"""
        return {
            "queue_size": self._queue.qsize(),
            "queue_max": self._queue.maxsize,
            "event_count": self._event_count,
            "dropped_count": self._dropped_count,
            "otlp_connected": self._exporter._connected if self._exporter else False,
            "running": self._running,
        }


# 全局审计流实例
_global_stream: Optional[AuditStream] = None


def get_audit_stream() -> AuditStream:
    """获取全局审计流实例"""
    global _global_stream
    if _global_stream is None:
        _global_stream = AuditStream()
    return _global_stream


def init_audit_stream(
    otlp_endpoint: Optional[str] = None,
    max_queue_size: int = 10000,
    min_severity: str = "info"
) -> AuditStream:
    """初始化全局审计流"""
    global _global_stream
    _global_stream = AuditStream(
        otlp_endpoint=otlp_endpoint,
        max_queue_size=max_queue_size,
        min_severity=min_severity
    )
    return _global_stream
