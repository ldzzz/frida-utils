from abc import ABC,abstractmethod 

class AbstractMonitor(ABC):

    @abstractmethod  
    def parse_payload(self, payload):
        """Parse payload and structure it for printing"""
        pass

    @abstractmethod
    def on_message(self, message, data):
        """Callback for js hook"""
        pass

    @abstractmethod
    def get_hook(self):
        """Attach corresponding Javascript hook file"""
        pass

    @abstractmethod  
    def run(self):
        """Run the hooking and printing"""
        pass