"""Queue SDK work bodies; thread/channel scheduling belongs to its app consumer."""
import copy
from dataclasses import dataclass
from fractions import Fraction
import math
import time

from . import netfunnel_protocol as protocol

EVENTS = {200, 201, 203, 204, 211, 300, 301, 302, 303, 500, 980, 981, 999}


@dataclass(frozen=True)
class Event:
    code: int
    error: int

    @property
    def success(self):
        return self.code in (200, 204, 300, 303, 980)

    @property
    def blocking(self):
        return self.code in (301, 302)


class Progress:
    def __init__(self):
        self.first = protocol.Response()
        self.current = protocol.Response()
        self.updates = self.notices = 0
        self.last_wait = 0.0

    def update(self, response):
        if self.updates == 0:
            self.first = copy.copy(response)
        self.current = copy.copy(response)
        self.updates += 1

    def wait_time(self):
        count = protocol.float32(str(self.current.nwait))
        tps = self.current.tps if self.current.tps > 0 else 1.0
        exact = Fraction(0) if math.isinf(tps) else Fraction(abs(count))/Fraction(tps)
        value = protocol.binary32(exact, 0x80000000 if count < 0 else 0)
        if self.last_wait == 0:
            self.last_wait = value
        return self.last_wait if value > self.last_wait else value


class Engine:
    def __init__(self, client, listeners=(), *, sleep=time.sleep, clock=time.time, load=lambda: True):
        self.client, self.listeners = client, listeners
        self.sleep, self.clock, self.load = sleep, clock, load
        self.stop_continue = False
        self.progress = Progress()

    def notice(self, code, error):
        if code in (500, 999) and self.client.properties.error_bypass:
            code = 980
        self.progress.notices += 1
        event = Event(code, error)
        for callback in self.listeners:
            try:
                callback(self, event)
            except Exception:
                pass

    def command(self, opcode):
        if opcode not in (5101, 5002, 5003, 5004):
            return 998
        counter = 0
        while True:
            try:
                self.client.execute(opcode)
                return 994 if opcode == 5003 and not self.client.response.key else 200
            except protocol.LocalError:
                raise
            except Exception:
                try:
                    self.sleep(1)
                    counter += 1
                except Exception:
                    # The outer native sleep catch does not advance its counter.
                    pass
            if counter > self.client.properties.retry:
                return 909

    def begin(self):
        properties = self.client.properties
        if properties.bypass:
            self.notice(204, 200)
            return
        if not self.load():
            self.notice(981, 928)
            return
        result = self.command(5101)
        if result != 200:
            self.notice(999, result)
            return
        self.progress = Progress()
        self.stop_continue = False
        previous_time = int(self.clock())
        while True:
            try:
                code = self.client.response.code
                if code not in (201, 202):
                    event = code if code in EVENTS else 999
                    self.notice(500 if event == 999 else event, code)
                    return
                self.progress.update(self.client.response)
                self.notice(201, code)
                ttl = self.client.response.wait_seconds(properties.max_ttl, 1)
                self.sleep(ttl)
                counter = 0
                while counter*2 <= ttl:
                    self.sleep(.5)
                    counter += 1
                    if self.stop_continue:
                        self.notice(203, 111)
                        return
                    if counter % 2 == 0:
                        self.notice(211, self.client.response.code)
                result = self.command(5002)
                if result != 200:
                    self.notice(999, result)
                    return
                now = int(self.clock())
                if properties.stale_count > 0 and properties.stale_seconds > 0 and now-previous_time >= properties.stale_seconds and self.client.response.nwait <= properties.stale_count:
                    self.notice(980, 908)
                    return
                previous_time = now
            except protocol.LocalError:
                raise
            except Exception:
                self.notice(999, 909)
                return

    def end(self):
        if self.client.properties.bypass or not self.client.response.key:
            return
        try:
            self.client.execute(5004)
        except protocol.LocalError:
            raise
        except Exception:
            pass  # Cleanup has no new SDK success/failure notification or retry.

    def alive(self):
        if self.client.properties.bypass or not self.client.response.key:
            return
        while self.command(5003) == 200:
            try:
                self.sleep(.5)
                self.sleep(self.client.response.wait_seconds(self.client.properties.max_ttl, 1))
            except Exception:
                return
