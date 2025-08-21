import re
from rich.progress import Progress

HOSTS_BAR_COLOR = "red"
STEPS_BAR_COLOR = "green"
SUBSTEP_BAR_COLOR = "blue"

class ProgressBar:
    def __init__(self, hosts, steps):
        self.hosts = hosts
        self.steps = steps

        self.progress = Progress()
        self.progress.start()
        self.hosts_bar = self.progress.add_task(f"[{HOSTS_BAR_COLOR}]Hosts", total = self.hosts)
        self.hosts_first = False
        self.steps_bar = self.progress.add_task(f"[{STEPS_BAR_COLOR}]", total = len(self.steps))
        self.steps_first = False
        self.substep_bar = self.progress.add_task(f"[{SUBSTEP_BAR_COLOR}]", total = 1000)
        self.segments = 1
        self.current_segment = 0

    def newHost(self, host):
        if self.hosts_first:
            self.progress.update(self.hosts_bar, advance = 1)
        else:
            self.hosts_first = True

        self.progress.reset(self.steps_bar, description = f"[{STEPS_BAR_COLOR}]Host {host}")
        self.steps_first = False
        self.progress.reset(self.substep_bar, description = f"[{SUBSTEP_BAR_COLOR}]Initialization")

    def newStep(self, step, segments = 1):
        if self.steps_first:
            self.progress.update(self.steps_bar, advance = 1)
        else:
            self.steps_first = True

        self.progress.reset(self.substep_bar, description = f"[{SUBSTEP_BAR_COLOR}]{self.steps[step]}")
        self.segments = segments
        self.current_segment = 0

    def newSegment(self):
        self.current_segment += 1

        if self.current_segment >= self.segments:
            self.segments = self.current_segment + 1

    def update(self, inner_progress):
        progress = (self.current_segment + inner_progress / 100) / self.segments
        self.progress.update(self.substep_bar, completed = int(progress * 1000))

    def complete(self):
        self.progress.update(self.hosts_bar, completed = float("infinity"))
        self.progress.update(self.steps_bar, visible = False)
        self.progress.update(self.substep_bar, visible = False)

    def end(self):
        self.progress.stop()