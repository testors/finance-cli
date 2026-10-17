"""Queue SDK listeners, deferred Handler callbacks and closing Flow delivery."""
import math
from . import netfunnel_notice as notice, netfunnel_protocol as protocol


def integer(value):
    if math.isnan(value): return 0
    if value >= 2**31-1: return 2**31-1
    if value <= -2**31: return -2**31
    return math.ceil(value)


class Callbacks:
    def __init__(self, enqueue, complete, fetch_notice, deliver, observe=lambda **values: None):
        self.enqueue, self.complete, self.fetch_notice = enqueue, complete, fetch_notice
        self.deliver, self.observe = deliver, observe
        self.closed = False
        self.listener = True

    def emit(self, kind, **value):
        if not self.listener: return
        self.observe(kind='callback', state=kind)
        if not self.closed:
            self.deliver(kind, value)
        if kind in ('BLOCK', 'END', 'UNVERIFIED'):
            self.closed = True

    def first(self, engine, event):
        # Retain the engine reference: the Handler reads current progress later.
        self.enqueue(lambda: self.handle(engine, event))

    def handle(self, engine, event):
        try:
            if not self.listener or event.code not in (201, 211): return
            if engine.progress.notices == 1:
                self.emit('START')
            if event.code == 211: return
            remaining = integer(engine.progress.wait_time())
            count = engine.progress.current.nwait
            properties = engine.client.properties
            if properties.ui_time_limit > 0 and remaining > properties.ui_time_limit:
                remaining = properties.ui_time_limit
            if properties.ui_count_limit > 0 and count > properties.ui_count_limit:
                count = properties.ui_time_limit  # Native field selection.
            self.emit('PROGRESS', remaining=remaining, count=count)
        except Exception:
            pass

    def second(self, engine, event):
        try:
            if event.code == 201:
                engine.progress.wait_time()
                return
            if event.blocking:
                text = self.fetch_notice()
                text = text.encode('iso-8859-1', errors='replace').decode('euc-kr', errors='replace')
                if self.listener:
                    self.emit('BLOCK', notice=notice.parse(text))
            self.complete()
        except protocol.LocalError:
            self.emit('UNVERIFIED')
            return
        except Exception:
            # The original catches notice transport/callback errors and still
            # queues onComplete, without making up the skipped END request.
            pass
        self.enqueue(self.handle_complete)

    def handle_complete(self):
        try:
            self.emit('END')
        except Exception:
            pass

    def cleanup(self):
        self.listener = False  # awaitClose does not call SDK END.
