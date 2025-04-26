import re
from tqdm import tqdm

class ProgressBar:
    def __init__(self, hosts, steps):
        self.hosts = hosts
        self.steps = steps

        self.hosts_bar = tqdm(total = self.hosts, desc = "Hosts")
        self.hosts_first = False
        self.steps_bar = tqdm(total = len(self.steps))
        self.steps_first = False
        self.substep_bar = tqdm(total = 1000)
        self.segments = 1
        self.current_segment = 0

    def newHost(self, host):
        if self.hosts_first:
            self.hosts_bar.update(1)
            self.hosts_bar.refresh()
        else:
            self.hosts_first = True

        self.steps_bar.reset()
        self.steps_bar.set_description("Host " + str(host))
        self.steps_first = False
        self.substep_bar.reset()
        self.substep_bar.set_description("Initialization")

    def newStep(self, step, segments = 1):
        if self.steps_first:
            self.steps_bar.update(1)
            self.steps_bar.refresh()
        else:
            self.steps_first = True

        self.substep_bar.reset()
        self.substep_bar.set_description(self.steps[step])
        self.segments = segments
        self.current_segment = 0

    def newSegment(self):
        self.current_segment += 1

        if self.current_segment >= self.segments:
            self.segments = self.current_segment + 1

    def update(self, inner_progress):
        progress = (self.current_segment + inner_progress / 100) / self.segments
        self.substep_bar.update(int(progress * 1000 - self.substep_bar.n))

    def print(self, *args):
        tqdm.write(" ".join(str(arg) for arg in args))

    def end(self):
        self.hosts_bar.update(self.hosts_bar.total - self.hosts_bar.n)
        self.steps_bar.update(self.steps_bar.total - self.steps_bar.n)
        self.substep_bar.update(self.substep_bar.total - self.substep_bar.n)