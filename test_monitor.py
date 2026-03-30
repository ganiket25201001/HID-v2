from core.usb_monitor import USBEventEmitter
from PySide6.QtWidgets import QApplication
import sys
import time

app = QApplication(sys.argv)
monitor = USBEventEmitter()

# Connect signal to print
from core.event_bus import event_bus
event_bus.usb_device_inserted.connect(lambda d: print(f"[EVENT] Inserted: {d['device_name']}"))
event_bus.usb_device_removed.connect(lambda d: print(f"[EVENT] Removed: {d['device_id']}"))

monitor.start()
print("USB Monitor started in SIMULATION_MODE")
print("Waiting 15 seconds for fake events...")

# Process Qt events so signals work while we wait
start_time = time.time()
while time.time() - start_time < 15:
    app.processEvents()
    time.sleep(0.1)

monitor.stop()
print("Test completed — check console for fake USB events")
